#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
# Copyright (c) 2019 @stoerchl
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


import re
import io
import os

import certstream
import entropy
import tqdm
import yaml
import base64
import urllib
import datetime
import time
import zipfile
import multiprocessing

from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld

from confusables import unconfuse
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

certstream_url = 'wss://certstream.calidog.io'
log_suspicious = 'suspicious_domains.log'

# MAIL Settings
mail_interval = 300 # in seconds
mail_from = "sender@gmail.com"
mail_to = "recipient@gmail.com"
smtp_server = "smtp.gmail.com"
smtp_port = 587
mail_login = "sender@gmail.com"
mail_password = "gmail_password"

# Progress bars
pbar1 = tqdm.tqdm(desc='certificate_update', unit=' cert', position=0)
pbar2 = tqdm.tqdm(desc='domain_analysis', unit=' domain', position=1)


def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy.shannon_entropy(domain)*50))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]
        # ie. detect fake .com (ie. *.com-account-management.info)
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


def score_evaluate(score, domain):
    # score >= 100: Very Suspicious
    # score >= 90: Suspisious
    # score >= 80: Likely
    # score >= 65: Potential
    if score >= 100:
        with open(log_suspicious, 'a') as f:
            f.write("{}\r\n".format(domain))


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar1.update(1)
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                score += 10

            score_evaluate(score, domain)


def domain_worker():
    saved_date = None
    while True:
        date = datetime.date.today() - datetime.timedelta(1)
        encoded_date = base64.b64encode((str(date) + ".zip").encode("utf-8"))
    
        if date != saved_date:
            try:
                req = urllib.request.Request('https://whoisds.com//whois-database/newly-registered-domains/'+str(encoded_date.decode("utf-8"))+'/nrd', headers={'User-Agent' : "Magic Browser"})
                filedata = urllib.request.urlopen(req)
                datatowrite = filedata.read()

                file_like_object = io.BytesIO(datatowrite)
                zipfile_ob = zipfile.ZipFile(file_like_object)
    
                new_domains = None
                for name in zipfile_ob.namelist():
                    data = zipfile_ob.read(name)
                    new_domains = str(data).split("\\r\\n")
                    break
    
                for d in new_domains:
                    pbar2.update(1)
                    score = score_domain(d.lower())
                    score_evaluate(score, d)
                
                saved_date = date

            except Exception:
                pass

        time.sleep(1800)


def cert_worker_error(instance, ex):
    time.sleep(10)


def cert_worker():
    # disable logger on console
    certstream.core.logging.getLogger().propagate = False
    certstream.core.logging.getLogger().disabled = True
    certstream.listen_for_events(callback, url=certstream_url, setup_logger=False, on_error=cert_worker_error)


# Mail helper: https://stackoverflow.com/questions/1966073/how-do-i-send-attachments-using-smtp
def mail_worker():

    while True:
        # Sleep for a while
        time.sleep(mail_interval)

        msg = MIMEMultipart()
        msg['From'] = mail_from
        msg['To'] = mail_to
        msg['Subject'] = 'Phishing Domain Analysis'
        message = 'Attached you find a List of suspicious Domains'
        msg.attach(MIMEText(message))

        # Roll Logfiles
        if os.path.isfile(log_suspicious):
            new_name = log_suspicious[:-4]+"_"+str(time.strftime("%d-%m-%Y_%H-%M"))+".log"
            os.rename(log_suspicious, new_name)
        else:
            continue

        try:
            filename=new_name
            fp=open(filename,'rb')
            att = MIMEApplication(fp.read(),_subtype="text/plain")
            fp.close()
            att.add_header('Content-Disposition','attachment',filename=filename)
            msg.attach(att)

            mailserver = smtplib.SMTP(smtp_server,smtp_port)
            # identify ourselves to smtp gmail client
            mailserver.ehlo()
            # secure our email with tls encryption
            mailserver.starttls()
            # re-identify ourselves as an encrypted connection
            mailserver.ehlo()
            mailserver.login(mail_login, mail_password)
            mailserver.sendmail(mail_from,mail_to,msg.as_string())

            mailserver.quit()
          
            os.rename(new_name, "processed/" + new_name)
        except:
            pass


if __name__ == '__main__':
    with open('suspicious.yaml', 'r') as f:
        suspicious = yaml.safe_load(f)

    with open('external.yaml', 'r') as f:
        external = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])
    
    certs = multiprocessing.Process(target=cert_worker)
    domains = multiprocessing.Process(target=domain_worker)
    mails = multiprocessing.Process(target=mail_worker)

    certs.start()
    domains.start()
    mails.start()
