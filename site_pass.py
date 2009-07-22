#!/usr/bin/env python

"""site_pass.py

A password utility for creating unique passwords per domain name using a single
master password.
"""
__author__  = "Ryan McGuire (ryan@enigmacurry.com)"

import getpass
import sys
import os
from hashlib import md5
import urlparse
import string
import random

#These are all the second level domains that are not sites in and of themselves
#We will always try to find a third level domain for domains ending in the
#following. I have no idea if this is a complete list (probably not).
bad_domain_endings = ['ab.ca', 'ac.ac', 'ac.at', 'ac.be', 'ac.cn', 'ac.il',
 'ac.in', 'ac.jp', 'ac.kr', 'ac.nz', 'ac.th', 'ac.uk', 'ac.za', 'adm.br',
 'adv.br', 'agro.pl', 'ah.cn', 'aid.pl', 'alt.za', 'am.br', 'arq.br', 'art.br',
 'arts.ro', 'asn.au', 'asso.fr', 'asso.mc', 'atm.pl', 'auto.pl', 'bbs.tr',
 'bc.ca', 'bio.br', 'biz.pl', 'bj.cn', 'br.com', 'cn.com', 'cng.br', 'cnt.br',
 'co.ac', 'co.at', 'co.il', 'co.in', 'co.jp', 'co.kr', 'co.nz', 'co.th', 'co.uk',
 'co.za', 'com.au', 'com.br', 'com.cn', 'com.ec', 'com.fr', 'com.hk', 'com.mm',
 'com.mx', 'com.pl', 'com.ro', 'com.ru', 'com.sg', 'com.tr', 'com.tw', 'cq.cn',
 'cri.nz', 'de.com', 'ecn.br', 'edu.au', 'edu.cn', 'edu.hk', 'edu.mm', 'edu.mx',
 'edu.pl', 'edu.tr', 'edu.za', 'eng.br', 'ernet.in', 'esp.br', 'etc.br',
 'eti.br', 'eu.com', 'eu.lv', 'fin.ec', 'firm.ro', 'fm.br', 'fot.br', 'fst.br',
 'g12.br', 'gb.com', 'gb.net', 'gd.cn', 'gen.nz', 'gmina.pl', 'go.jp', 'go.kr',
 'go.th', 'gob.mx', 'gov.br', 'gov.cn', 'gov.ec', 'gov.il', 'gov.in', 'gov.mm',
 'gov.mx', 'gov.sg', 'gov.tr', 'gov.za', 'govt.nz', 'gs.cn', 'gsm.pl', 'gv.ac',
 'gv.at', 'gx.cn', 'gz.cn', 'hb.cn', 'he.cn', 'hi.cn', 'hk.cn', 'hl.cn', 'hn.cn',
 'hu.com', 'idv.tw', 'ind.br', 'inf.br', 'info.pl', 'info.ro', 'iwi.nz', 'jl.cn',
 'jor.br', 'jpn.com', 'js.cn', 'k12.il', 'k12.tr', 'lel.br', 'ln.cn', 'ltd.uk',
 'mail.pl', 'maori.nz', 'mb.ca', 'me.uk', 'med.br', 'med.ec', 'media.pl',
 'mi.th', 'miasta.pl', 'mil.br', 'mil.ec', 'mil.nz', 'mil.pl', 'mil.tr',
 'mil.za', 'mo.cn', 'muni.il', 'nb.ca', 'ne.jp', 'ne.kr', 'net.au', 'net.br',
 'net.cn', 'net.ec', 'net.hk', 'net.il', 'net.in', 'net.mm', 'net.mx', 'net.nz',
 'net.pl', 'net.ru', 'net.sg', 'net.th', 'net.tr', 'net.tw', 'net.za', 'nf.ca',
 'ngo.za', 'nm.cn', 'nm.kr', 'no.com', 'nom.br', 'nom.pl', 'nom.ro', 'nom.za',
 'ns.ca', 'nt.ca', 'nt.ro', 'ntr.br', 'nx.cn', 'odo.br', 'on.ca', 'or.ac',
 'or.at', 'or.jp', 'or.kr', 'or.th', 'org.au', 'org.br', 'org.cn', 'org.ec',
 'org.hk', 'org.il', 'org.mm', 'org.mx', 'org.nz', 'org.pl', 'org.ro', 'org.ru',
 'org.sg', 'org.tr', 'org.tw', 'org.uk', 'org.za', 'pc.pl', 'pe.ca', 'plc.uk',
 'ppg.br', 'presse.fr', 'priv.pl', 'pro.br', 'psc.br', 'psi.br', 'qc.ca',
 'qc.com', 'qh.cn', 're.kr', 'realestate.pl', 'rec.br', 'rec.ro', 'rel.pl',
 'res.in', 'ru.com', 'sa.com', 'sc.cn', 'school.nz', 'school.za', 'se.com',
 'se.net', 'sh.cn', 'shop.pl', 'sk.ca', 'sklep.pl', 'slg.br', 'sn.cn', 'sos.pl',
 'store.ro', 'targi.pl', 'tj.cn', 'tm.fr', 'tm.mc', 'tm.pl', 'tm.ro', 'tm.za',
 'tmp.br', 'tourism.pl', 'travel.pl', 'tur.br', 'turystyka.pl', 'tv.br', 'tw.cn',
 'uk.co', 'uk.com', 'uk.net', 'us.com', 'uy.com', 'vet.br', 'web.za', 'web.com',
 'www.ro', 'xj.cn', 'xz.cn', 'yk.ca', 'yn.cn', 'za.com']

############################
# Allowed character classes
############################

all_printable = "".join([chr(x) for x in range(32,127)])
all_printable_without_space = "".join([chr(x) for x in range(33,127)])
alpha_numeric = string.ascii_letters + string.digits

class URLParseException(Exception):
    pass

def extract_domain(url):
    url = url.strip()
    full_domain = urlparse.urlparse(url)[1]
    if full_domain == "":
        #The URL didn't parse, probably because it didn't have a protocol.
        #Take everything up to the first / instead
        full_domain = url.split("/")[0]
        if full_domain == "":
            #Still nothing,
            raise URLParseException("Cannot parse url: '%s'" % url)
    full_domain = full_domain.split(":")[0] #strip off port numbers
    parts = full_domain.split(".")
    if len(parts) < 2:
        raise URLParseException("URLs must have at least one dot")
    if ".".join(parts[-2:]) in bad_domain_endings:
        #Since this is in a bad 2nd level domain, return a third level domain.
        return ".".join(parts[-3:])
    else:
        #Return the standard second level domain.
        return ".".join(parts[-2:])

def hash_url_legacy(url, passphrase,length=8):
    """Create a password based on a function of the domain"""
    domain = extract_domain(url)
    md5_pass = md5(domain+"|"+passphrase).hexdigest()
    #Compress the md5 digest by converting bytes 20 - 7E to their ASCII version
    pw_parts = []
    for x in range(0,32,2):
        byte = int(md5_pass[x:x+2],16)
        if byte < 32 or byte > 126:
            #Byte is not printable, leave alone
            pw_parts.append(md5_pass[x:x+2])
        else:
            pw_parts.append(chr(byte))
    pw = "".join(pw_parts)
    return pw[0:length]

def hash_url(url, passphrase, length=16,
             allowed_chars=all_printable_without_space):
    domain = extract_domain(url)
    md5_pass = md5(domain+"|"+passphrase).hexdigest()
    #Compress the md5 digest by converting bytes 20 - 7E to their ASCII version
    pw_parts = []
    for x in range(0,32,2):
        byte = int(md5_pass[x:x+2],16)
        if chr(byte) not in allowed_chars:
            #Byte is not allowed, leave as hex
            pw_parts.append(md5_pass[x:x+2])
        else:
            pw_parts.append(chr(byte))
    pw = "".join(pw_parts)
    return pw[0:length]

if __name__ == "__main__":
    print("############################ WARNING ############################")
    print("DO NOT run this on machines you don't own personally.")
    print("Your passphrase is stored in memory and may be seen by root.")
    print("It is also recomended that you run an encrypted swap device.")
    print("############################ WARNING ############################")
    print("")
    #Read in the known passphrase hash
    hash_filename = os.path.join(os.environ['HOME'],".EC_sitepass")
    if os.path.isfile(hash_filename):
        passphrase = getpass.getpass("Enter your passphrase: ")
        salt, known_hash = open(hash_filename).read().split("|")
        while (known_hash != md5(salt+passphrase).hexdigest()):
            passphrase = getpass.getpass(
                "Incorrect Passphrase, Enter your passphrase:")
    else:
        print("")
        print("No configuration data found, setting up a new passphrase.")
        passphrase = getpass.getpass("Enter a new passphrase: ")
        passphrase_verify = getpass.getpass("Enter passphrase again: ")
        if passphrase != passphrase_verify:
            print("You didn't type the same passphrase both times")
            sys.exit(1)
        known_hash = open(hash_filename,"w")
        salt = "".join([random.choice(alpha_numeric) for x in range(0,10)])
        known_hash.write(salt+"|"+md5(salt+passphrase).hexdigest())
        known_hash.close()
    
    while True:
        print("")
        url = raw_input("Enter URL : ")
        try:
            print "Domain              : " + extract_domain(url)
            print("Password            : " + hash_url(
                    url,passphrase,length=16,allowed_chars=all_printable_without_space))
            print("Alpha-Num password  : " + hash_url(
                    url,passphrase,length=8,allowed_chars=alpha_numeric))
            print("Legacy password     : " + hash_url(
                    url,passphrase,length=8,allowed_chars=all_printable))
        except URLParseException, e:
            print e

        
