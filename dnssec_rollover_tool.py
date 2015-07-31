#!/usr/bin/python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8
'''Tool to print metadata of DNSSEC keys and perform key rollovers.

This tool is intended to help system administrators on DNSSEC key
rollovers. It can display the metadata of the keys for a zone and also
perform rollovers. Rollovers will be performed using the metadata of keys.
So it is intended to be used with the 'auto-dnssec maintain' statement for
BIND9.7+.
'''

__author__     = 'Sebastian Kricner'
__maintainer__ = 'Sebastian Kricner'
__email__      = 'sebastian.kricner@tuxwave.net'
__copyright__  = 'June 2015 tuxwave.net'
__license__    = 'GPL'
__version__    = '1.0'

import sys
import argparse
import errno
import os
import re
from pathlib import Path
from datetime import datetime, timedelta
from configparser import RawConfigParser
import locale
from subprocess import (call, check_output, Popen, PIPE, DEVNULL,
        CalledProcessError)
from email.mime.text import MIMEText
from pwd import getpwnam

class DNSSECKey:
    '''DNSSEC key object'''
    created  = None
    publish  = None
    activate = None
    revoke   = None
    inactive = None
    delete   = None
    keyfile  = None
    keytype  = None
    keyid    = None
    key_name = None
    ds_ttl   = None
    def __init__(self, keyfile):
        self.keyfile = str(keyfile)
        self._readkey()
    def _readkey(self):
        '''Read key metadata'''
        with open(self.keyfile) as filedesc:
            for line in filedesc:
                matchresult = re.match(
                    "^; This is a (\w+)-signing key, keyid (\d+), for (.*)$",
                    line)
                if matchresult:
                    self.keytype = matchresult.group(1)
                    self.keyid = matchresult.group(2)
                    self.key_name = matchresult.group(3)
                    continue
                matchresult = re.match( "^; Created: (\d{14}).*", line)
                if matchresult:
                    self.created = datetime.strptime(
                        matchresult.group(1),
                        "%Y%m%d%H%M%S")
                    continue
                matchresult = re.match("^; Publish: (\d{14}).*", line)
                if matchresult:
                    self.publish = datetime.strptime(
                        matchresult.group(1),
                        "%Y%m%d%H%M%S")
                    continue
                matchresult = re.match("^; Activate: (\d{14}).*", line)
                if matchresult:
                    self.activate = datetime.strptime(
                        matchresult.group(1),
                        "%Y%m%d%H%M%S")
                    continue
                matchresult = re.match("^; Revoke: (\d{14}).*", line)
                if matchresult:
                    self.revoke = datetime.strptime(
                        matchresult.group(1),
                        "%Y%m%d%H%M%S")
                    continue
                matchresult = re.match("^; Inactive: (\d{14}).*", line)
                if matchresult:
                    self.inactive = datetime.strptime(
                        matchresult.group(1),
                        "%Y%m%d%H%M%S")
                    continue
                matchresult = re.match("^; Delete: (\d{14}).*", line)
                if matchresult:
                    self.delete = datetime.strptime(
                        matchresult.group(1),
                        "%Y%m%d%H%M%S")
                    continue
    def status(self):
        '''Return key status'''
        current_time = datetime.now()
        if self.delete and self.delete < current_time:
            return "deleted"
        if self.inactive and self.inactive < current_time:
            return "inactivated"
        if self.revoke and self.revoke < current_time:
            return "revoked"
        if self.activate and self.activate < current_time:
            return "activated"
        if self.publish and self.publish < current_time:
            return "published"
        if self.publish and self.publish < current_time:
            return "created"
    def dsfromkey(self):
        '''Get DS from key'''
        if self.keytype == 'key':
            try:
                dnssec_dsfromkey = check_output(
                    [
                        'dnssec-dsfromkey',
                        self.keyfile
                    ],
                    stderr=DEVNULL)
                if dnssec_dsfromkey:
                    return dnssec_dsfromkey.decode(
                            locale.getpreferredencoding(False)).strip()
            except CalledProcessError:
                return
    def check_ds(self):
        '''Check DS of key is in DNS'''
        dsfromkey = self.dsfromkey()
        if dsfromkey:
            try:
                dig = check_output(
                    [
                        'dig',
                        '+trace',
                        '+noall',
                        '+nodnssec',
                        '+noidentify',
                        '+ttlid',
                        '+nosplit',
                        '+answer',
                        'ds',
                        self.key_name
                    ],
                    stderr=DEVNULL)
                if dig:
                    for digline in dig.decode(
                            locale.getpreferredencoding(False)
                            ).strip().split('\n'):
                        fields = digline.split()
                        if len(fields) > 3 and fields[3] == 'DS':
                            ds_ttl = int(fields.pop(1))
                            ds = ' '.join(fields)
                            if ds in dsfromkey.split('\n'):
                                self.ds_ttl = ds_ttl
                                return True
                return False
            except CalledProcessError:
                return
    def get_ds_ttl(self):
        '''Return DS TTL in DNS'''
        if self.ds_ttl:
            return self.ds_ttl
        elif self.check_ds():
            if self.ds_ttl:
                return self.ds_ttl
    def get_soa_params(self):
        '''Get SOA params of zone in DNS [refresh, retry, expire]'''
        try:
            dig = check_output(
                [
                    'dig',
                    '+trace',
                    '+noall',
                    '+nodnssec',
                    '+noidentify',
                    '+ttlid',
                    '+nosplit',
                    '+answer',
                    'soa',
                    self.key_name
                ],
                stderr=DEVNULL)
            if dig:
                for dig in dig.decode(
                        locale.getpreferredencoding(False)).split('\n'):
                    matchresult = re.match(
                        '^[^ ]*\s+\d+\s+IN\s+SOA'
                        '\s+[^ ]*\s+[^ ]*\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+',
                        dig)
                    if matchresult:
                        return [int(matchresult.group(x)) for x in range(1,4)]
        except CalledProcessError:
            return
    def __str__(self):
        '''Return human readable key representation'''
        dsfromkey = self.dsfromkey()
        return 'F:'  ' {0.keyfile}\n'  \
               'N:'  ' {0.key_name} '  \
               'ID:' ' {0.keyid} '    \
               'T:'  ' {0.keytype}\n'  \
               'C:'  ' {0.created} '   \
               'P:'  ' {0.publish} '   \
               'A:'  ' {0.activate} '  \
               'R:'  ' {0.revoke} '    \
               'I:'  ' {0.inactive} '  \
               'D:'  ' {0.delete}\n'   \
               'S:'  ' {1} {2}{3}'.format(self, self.status(),
               'DSinDNS: ' + str(
                self.check_ds()) if dsfromkey else
                '', '\n' + dsfromkey if dsfromkey else '')
    def __nonzero(self):
        '''Return whether key metadata was available'''
        return bool(self.keytype)

class DNSSECRollover():
    '''Object to handle DNSSEC key rollovers'''
    dnssec_keys = []
    dnssec_keys_filtered_sorted = []
    def __init__(
        self,
        keytype,
        interval,
        resign_interval,
        email_from,
        email_to,
        keyfileowner,
        dnssec_keys = []
    ):
        '''Perform rollover'''
        self.keytype = keytype
        self.interval = interval
        self.resign_interval = resign_interval
        self.dnssec_keys = dnssec_keys
        self.email_from = email_from
        self.email_to = email_to
        self.keyfileowner = keyfileowner
        if self.dnssec_keys:
            self.dnssec_keys_filtered_sorted = self.filter_sort_keys()
            if self.check_new_key_generation():
                self.generate_new_key()
                self.chown()
            if self.keytype == 'key':
                self.inactivate_delete_old_ksk()
                self.check_ksk_ds_email()
            self.delete_deleted_keys()
    def check_new_key_generation(self):
        '''Check whether a new key is required to be generated'''
        prepublish_time = self.calculate_time()
        dnssec_keys = self.filter_sort_keys('activated published None')
        if self.keytype == 'zone' and prepublish_time:
            if dnssec_keys[-1].activate + prepublish_time < datetime.now():
                    return True
        elif self.keytype == 'key' and prepublish_time:
            if dnssec_keys[-1].activate + prepublish_time < datetime.now():
                return True
    def generate_new_key(self):
        '''Generate a new key'''
        prepublish_time = self.calculate_time(True)
        postpublish_time = self.calculate_time(True, 'post_publish')
        prepublish_interval = self.calculate_time()
        postpublish_interval = self.calculate_time(wanted = 'post_publish')
        if not (prepublish_time and
                    postpublish_time and
                    prepublish_interval and
                    postpublish_interval):
            return
        if self.keytype == 'zone':
            if not call(
                [
                    'dnssec-settime',
                    '-I', '+' + str(int(prepublish_time.total_seconds())),
                    '-D', '+' + str(int(postpublish_time.total_seconds())),
                    self.dnssec_keys_filtered_sorted[-1].keyfile,
                ], stdout=DEVNULL, stderr=DEVNULL):
                if not call([
                                'dnssec-keygen',
                                '-b',
                                '1024',
                                '-K',
                                os.path.dirname(
                                self.dnssec_keys_filtered_sorted[-1].keyfile),
                                '-S',
                                self.dnssec_keys_filtered_sorted[-1].keyfile,
                                '-i',
                                str(int(prepublish_interval.total_seconds())),
                            ], stdout=DEVNULL, stderr=DEVNULL):
                    return
            call([
                    'dnssec-settime',
                    '-I',
                    'none',
                    '-D',
                    'none',
                    self.dnssec_keys_filtered_sorted[-1].keyfile,
                ], stdout=DEVNULL, stderr=DEVNULL)
        elif self.keytype == 'key':
            try:
                newkey = check_output([
                                'dnssec-keygen',
                                '-K',
                                os.path.dirname(
                                self.dnssec_keys_filtered_sorted[-1].keyfile),
                                '-A',
                                '+' + str(self.interval),
                                '-i',
                                str(int(prepublish_interval.total_seconds())),
                                '-f',
                                'KSK',
                                '-n',
                                'ZONE',
                                '-a',
                                'RSASHA256',
                                '-b',
                                '2048',
                                self.dnssec_keys_filtered_sorted[-1].key_name,
                            ], stderr=DEVNULL)
                if newkey:
                    newkey = newkey.decode(
                                locale.getpreferredencoding(False)
                            ).strip()
                    newkey_file = os.path.join(
                        os.path.dirname(
                            self.dnssec_keys_filtered_sorted[-1].keyfile),
                            newkey + '.key')
                    if os.path.isfile(newkey_file):
                        self.dnssec_keys.append(DNSSECKey(newkey_file))
            except CalledProcessError:
                return
    def chown(self):
        for dnssec_key in self.dnssec_keys:
            os.chown(
                dnssec_key.keyfile,
                getpwnam(self.keyfileowner).pw_uid,
                getpwnam(self.keyfileowner).pw_gid
            )
            if os.path.isfile(dnssec_key.keyfile.replace('.key', '.private')):
                os.chown(
                    dnssec_key.keyfile.replace('.key', '.private'),
                    getpwnam(self.keyfileowner).pw_uid,
                    getpwnam(self.keyfileowner).pw_gid
                )
    def inactivate_delete_old_ksk(self):
        '''Set inactivation (prepublish_interval) and
        deletion (postpublish_interval) on old KSK if
        latest KSK has DS record in DNS.'''
        dnssec_keys = self.filter_sort_keys('activated published')
        if dnssec_keys[-1].check_ds():
            if len(dnssec_keys) > 1:
                prepublish_interval = self.calculate_time()
                postpublish_interval = self.calculate_time(
                        wanted = 'post_publish',
                        current_ksk = dnssec_keys[-1])
                for dnssec_key in dnssec_keys[:-1]:
                    call([
                            'dnssec-settime',
                            '-I',
                            '+' + str(
                                    int(prepublish_interval.total_seconds())),
                            '-D',
                            '+' + str(
                                    int(postpublish_interval.total_seconds())),
                            dnssec_key.keyfile,
                        ], stdout=DEVNULL, stderr=DEVNULL)
    def check_ksk_ds_email(self):
        '''If DS of latest published KSK or active KSK
        is not in DNS, send a E-Mail.'''
        dnssec_keys_without_ds = [
                x for x in self.filter_sort_keys(
                    'activated published'
                    ) if not x.check_ds()
                ]
        for dnssec_key in dnssec_keys_without_ds:
            self.send_email(
                    'DS record insertion required',
                    'DNSSEC KSK with state "' +
                    str(dnssec_key.status()) +
                    '" found.\n'
                    'But DS record is not present in the parent zone.\n'
                    'Please insert following DS record into the parent zone:'
                    '\n\n' + dnssec_key.dsfromkey()
                    )
    def delete_deleted_keys(self):
        '''Delete keys flagged as deleted not having DS in DNS.
        Send E-Mail of DS to remove if key is KSK and DS in DNS.'''
        dnssec_keys = self.filter_sort_keys('deleted')
        if self.keytype == 'key':
            dnssec_keys_with_ds = [x for x in dnssec_keys if x.check_ds()]
            dnssec_keys_without_ds = [
                    x for x in dnssec_keys if not x.check_ds()
                    ]
            for dnssec_key in dnssec_keys_without_ds:
                os.unlink(dnssec_key.keyfile)
                if os.path.isfile(
                        dnssec_key.keyfile.replace('.key', '.private')
                        ):
                    os.unlink(dnssec_key.keyfile.replace('.key', '.private'))
            for dnssec_key in dnssec_keys_with_ds:
                self.send_email(
                        'DS record removal required',
                        'Deleted DNSSEC KSK has still a '
                        'DS record in the parent zone.\n'
                        'Please remove following DS record:\n\n'
                        + dnssec_key.dsfromkey()
                        )
        elif self.keytype == 'zone':
            for dnssec_key in dnssec_keys:
                os.unlink(dnssec_key.keyfile)
                if os.path.isfile(
                        dnssec_key.keyfile.replace('.key', '.private')
                        ):
                    os.unlink(dnssec_key.keyfile.replace('.key', '.private'))
    def send_email(self, subject, message):
        '''Send notification E-Mail'''
        msg = MIMEText(message)
        msg['From'] = self.email_from
        msg['To'] = self.email_to
        msg['Subject'] = subject
        sendmail = Popen(
            [
                '/usr/sbin/sendmail',
                '-t',
                '-oi'
            ], stdin = PIPE, stdout=DEVNULL, stderr=None)
        sendmail.communicate(bytes(msg.as_string(), 'utf-8'))
    def filter_sort_keys(self, status = 'activated'):
        '''Filter and sort keys'''
        dnssec_keys_filtered_sorted = [
                x for x in self.dnssec_keys if (x.keytype == self.keytype) and
                (str(x.status()) in status.split()) ]
        dnssec_keys_filtered_sorted = sorted(
            dnssec_keys_filtered_sorted,
            key = lambda x: x.activate or datetime.fromtimestamp(0)
        )
        return dnssec_keys_filtered_sorted
    def calculate_time(
        self,
        calculate_timeoffset = False,
        wanted = 'pre_publish',
        current_ksk = None
    ):
        '''Calculate pre/post publication time'''
        dnssec_keys = [x for x in self.dnssec_keys
                if x.keytype == self.keytype]
        soa_refresh, soa_retry, soa_expire = dnssec_keys[-1].get_soa_params()
        ds_ttl = 0
        if wanted == 'pre_publish':
            if calculate_timeoffset:
                return timedelta(seconds = self.interval -
                        (soa_expire + ((soa_refresh + soa_retry) * 3) +
                        ds_ttl))
            else:
                return timedelta(seconds = soa_expire +
                        ((soa_refresh + soa_retry) * 3) +
                        ds_ttl)
        if wanted == 'post_publish':
            if self.keytype == 'key':
                if not current_ksk:
                    for key in dnssec_keys:
                        ds_ttl = key.get_ds_ttl()
                        if ds_ttl:
                            break
                else:
                    ds_ttl = current_ksk.get_ds_ttl()
                if not ds_ttl:
                    return timedelta(seconds = ds_ttl)
            if calculate_timeoffset:
                return timedelta(seconds = self.interval +
                        (soa_expire + ((soa_refresh + soa_retry) * 3) +
                        self.resign_interval +
                        ds_ttl))
            else:
                return timedelta(seconds = soa_expire +
                        ((soa_refresh + soa_retry) * 3) +
                        self.resign_interval +
                        ds_ttl)

def warning(messageprefix, exitcode):
    '''Print warning message'''
    print("[warning]: "+messageprefix+os.strerror(exitcode))

def error(messageprefix, exitcode):
    '''Print error message and exit'''
    print("[error]: "+messageprefix+os.strerror(exitcode))
    sys.exit(exitcode)

def getkeys(path, zone):
    '''List of valid keys related to a zone from directory'''
    requestedpath = Path(path)
    keyfiles = sorted(requestedpath.glob("K"+zone+".*.key"))
    dnssec_keys = []
    if not keyfiles:
        error(
            "Unable to get keys for zone "+zone+" in directory '"+path+"': ",
            errno.ENOENT
        )
    for keyfile in keyfiles:
        dnssec_key = DNSSECKey(keyfile)
        if dnssec_key:
            dnssec_keys.append(dnssec_key)
    return dnssec_keys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Helps you with handling key rollovers',
        epilog='Re-sign interval is determined by BIND option '
        'sig-validity-interval. '
        'Example: '
        'sig-validity-interval 21 16 -> 21-16 = 5 days, '
        'so 432000 seconds. '
        'Good generic parameters for rollovers are: '
        'ZSK -> 2592000 432000 KSK -> 15552000 432000'
    )
    parser.add_argument(
        '-n',
        '--name',
        help='Name of the zone for which we will analyse keys.',
        required=True
    )
    parser.add_argument(
        '-d',
        '--directory',
        help='Directory where the key files reside.',
        required=True
    )
    parser.add_argument(
        '-r',
        '--rules',
        help='File containing rullover rules.',
        type=str
    )
    parser.add_argument(
        '-z',
        '--zskroll',
        help='Rollover ZSK on provided interval and re-sign interval.',
        type=int,
        nargs=2
    )
    parser.add_argument(
        '-k',
        '--kskroll',
        help='Rollover KSK on provided interval and re-sign interval.',
        type=int,
        nargs=2
    )
    parser.add_argument(
        '-e',
        '--email',
        help='From and To E-Mail addresses for DS notification.',
        type=str,
        nargs=2
    )
    parser.add_argument(
        '-o',
        '--owner',
        help='Owner to chown key files to.',
        type=str
    )
    parser.add_argument(
        '-p',
        '--print',
        help='Display the keys and sort by attribute. '
        'Attributes are Created, '
        'Publish (default), '
        'Activation, '
        'Revoke, '
        'Inactivate and '
        'Delete dates.',
        type=str,
        choices =['C', 'P', 'A', 'R', 'I', 'D']
    )
    args=parser.parse_args()

    if(args.zskroll):
        if not(args.owner):
            print('[error]: No key file owner specified.', file=sys.stderr)
            sys.exit(1)
        dnssec_rollover = DNSSECRollover(
            'zone',
            args.zskroll[0],
            args.zskroll[1],
            args.email[0],
            args.email[1],
            args.owner,
            getkeys(args.directory, args.name))

    if(args.kskroll):
        if not(args.email):
            print('[error]: No e-mail addresses specified', file=sys.stderr)
            sys.exit(1)
        if not(args.owner):
            print('[error]: No key file owner specified.', file=sys.stderr)
            sys.exit(1)
        dnssec_rollover = DNSSECRollover(
            'key',
            args.kskroll[0],
            args.kskroll[1],
            args.email[0],
            args.email[1],
            args.owner,
            getkeys(args.directory, args.name))
    
    if(args.print):
        sort_arg = {
            'C': 'created',
            'P': 'publish',
            'A': 'activate',
            'R': 'revoke',
            'I': 'inactive',
            'D': 'delete'
        }
        sorting_key = sort_arg[args.print]
        dnssec_keys = sorted(
            getkeys(args.directory, args.name),
            key = lambda x: (
                eval('x.'+sorting_key) or datetime.fromtimestamp(0),
                x.keytype,
                x.status() or ''))
        for dnssec_key in dnssec_keys:
            print('-'*75)
            print(dnssec_key)
        print('-'*75)
