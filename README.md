# Phishing catcher

Catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream.

This is a fork of the original phishing_catcher (https://github.com/x0rz/phishing_catcher) project.

### Changes

- Newly registered domains

  As a second source to catch potential phishing sites I added newly registered domains. They are published one a day and can be evaluated with the same algorithm as the certificates. Source (https://whoisds.com/newly-registered-domains)

- Email notification

  Sending the found potential phishing domains by email to a given address in a defined time interval.


### Installation

The script should work fine using Python2 or Python3.

You will need the following python packages installed: certstream, tqdm, entropy, termcolor, tld, python_Levenshtein

```sh
pip install -r requirements.txt
```


### Usage

```
$ ./catch_phishing.py
```
To run it in the background the script can be started in a screen session.

License
----
GNU GPLv3
