#!/usr/bin/python3

# Pytab for reading keytab and kerberos credential cache files
# Copyright 2022 Thomas Karlsson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# thomas karlsson relea se

import os
import base64
from typing import List, Tuple
# from asn1crypto.parser import parse  # type: ignore

# From https://www.rfc-editor.org/rfc/rfc4120 7.5.8
name_types = {
    0: 'KRB_NT_UNKNOWN',         # Name type not known
    1: 'KRB_NT_PRINCIPAL',       # Just the name of the principal as in DCE, or for users
    2: 'KRB_NT_SRV_INST',        # Service and other unique instance (krbtgt)
    3: 'KRB_NT_SRV_HST',         # Service with host name as instance (telnet, rcommands)
    4: 'KRB_NT_SRV_XHST',        # Service with host as remaining components
    5: 'KRB_NT_UID',             # Unique ID
    6: 'KRB_NT_X500_PRINCIPAL',  # Encoded X.509 Distinguished name [RFC2253]
    7: 'KRB_NT_SMTP_NAME',       # Name in form of SMTP email name (e.g., user@example.com)
    8: 'KRB_NT_ENTERPRISE'       # Enterprise name; may be mapped to
}

encryption_types = {
    1: 'des-cbc-crc',                    # 6.2.3
    2: 'des-cbc-md4',                    # 6.2.2
    3: 'des-cbc-md5',                    # 6.2.1
    4: '[reserved]',                     #
    5: 'des3-cbc-md5',                   #
    6: '[reserved]',                     #
    7: 'des3-cbc-sha1',                  #
    9: 'dsaWithSHA1-CmsOID',             # (pkinit)
    10: 'md5WithRSAEncryption-CmsOID',   # (pkinit)
    11: 'sha1WithRSAEncryption-CmsOID',  # (pkinit)
    12: 'rc2CBC-EnvOID',                 # (pkinit)
    13: 'rsaEncryption-EnvOID',          # (pkinit from PKCS#1 v1.5)
    14: 'rsaES-OAEP-ENV-OID',            # (pkinit from PKCS#1 v2.0)
    15: 'des-ede3-cbc-Env-OID',          # (pkinit)
    16: 'des3-cbc-sha1-kd',              # 6.3
    17: 'aes128-cts-hmac-sha1-96',       # [KRB5-AES]
    18: 'aes256-cts-hmac-sha1-96',       # [KRB5-AES]
    23: 'rc4-hmac',                      # (Microsoft)
    24: 'rc4-hmac-exp',                  # (Microsoft)
    65: 'subkey-keymaterial'             # (opaque; PacketCable)
}

tag_types = {
    1: 'Deltatime'
}

# Ticket flags
RESERVED = 2147483648
FORWARDABLE = 1073741824
FORWARDED = 536870912
PROXIABLE = 268435456
PROXY = 134217728
MAY_POSTDATE = 67108864
POSTDATED = 33554432
INVALID = 16777216
RENEWABLE = 8388608
INITIAL = 4194304
PRE_AUTHENTICATION = 2097152
HARDWARE_AUTHENTICATION = 1048576
TRANSITED_POLICY_CHECKED = 524288
OK_AS_DELEGATE = 262144


class keyentry():
    def __init__(self):
        self._principal: List[str] = []
        self._realm: str = str()
        self._name_type: int = 0
        self._timestamp: int = 0
        self._kvno: int = 0
        self._kvno_extended: int = 0
        self._encryption_type: int = 0
        self._key: bytes = b''
        self.deleted: bool = False

    @property
    def principal(self) -> List[str]:
        return self._principal

    @principal.setter
    def principal(self, add_principal: str):
        self._principal.append(add_principal)

    @property
    def name_type(self) -> int:
        return self._name_type

    @name_type.setter
    def name_type(self, new_type: int):
        if new_type in name_types:
            self._name_type = new_type

    @property
    def name_type_name(self) -> str:
        return name_types[self.name_type]

    @property
    def realm(self) -> str:
        return self._realm

    @realm.setter
    def realm(self, new_realm: str):
        self._realm = new_realm

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, new_time: int):
        self._timestamp = new_time

    @property
    def kvno(self) -> int:
        return self._kvno

    @kvno.setter
    def kvno(self, new_kvno: int):
        self._kvno = new_kvno

    @property
    def kvno_extended(self) -> int:
        return self._kvno_extended

    @kvno_extended.setter
    def kvno_extended(self, new_kvno: int):
        self._kvno_extended = new_kvno
        self._kvno = self._kvno_extended & 0xff

    @property
    def encryption_type(self) -> int:
        return self._encryption_type

    @encryption_type.setter
    def encryption_type(self, new_type: int):
        if new_type in encryption_types:
            self._encryption_type = new_type

    @property
    def encryption_name(self) -> str:
        return encryption_types[self.encryption_type]

    @property
    def key(self) -> bytes:
        return self._key

    @key.setter
    def key(self, new_key: bytes):
        self._key = new_key

    def key_base64(self) -> str:
        return base64.b64encode(self.key).decode()

    @property
    def spn(self) -> str:
        return '/'.join(self.principal) + '@' + self.realm

    def export(self) -> bytes:
        export_data = bytes()

        export_data = export_data + len(self.principal).to_bytes(2, "big")

        export_realm = len(self.realm).to_bytes(2, "big")
        export_realm = export_realm + self.realm.encode()
        export_data = export_data + export_realm

        export_principal = bytes()
        for component in range(len(self.principal)):
            principal_length = len(self.principal[component]).to_bytes(2, "big")
            export_principal = export_principal + principal_length + self.principal[component].encode()
        export_data = export_data + export_principal

        export_data = export_data + self.name_type.to_bytes(4, "big")

        export_data = export_data + self.timestamp.to_bytes(4, "big")

        export_data = export_data + self.kvno.to_bytes(1, "big")

        export_data = export_data + self.encryption_type.to_bytes(2, "big")

        export_data = export_data + len(self.key).to_bytes(2, "big")
        export_data = export_data + self.key

        if self.kvno_extended:
            export_data = export_data + self.kvno_extended.to_bytes(4, "big")

        if self.deleted is False:
            export_data = len(export_data).to_bytes(4, "big") + export_data
        else:
            new_length = len(export_data) | 0x80000000
            export_data = new_length.to_bytes(4, "big") + export_data

        return export_data


class keytab():
    def __init__(self):
        self.magic_header = 5
        self.keytab_version = 0
        self.num_components = 0
        self.key_entries = list()
        self._keytabfile: str = ''

    def convert_to_integer(self, value) -> int:
        if self.keytab_version == 2:
            returning = int.from_bytes(value, "big")
            return returning

        return value

    def read_str(self, filedata, index, str_length: int = 2):
        length = self.convert_to_integer(filedata[index:index + str_length])
        index += str_length
        retdata = filedata[index:index + length]
        index += length

        return int(index), retdata

    def read_bytes(self, filedata, index, read_length):
        retdata = filedata[index:index + read_length]
        index += read_length

        return index, retdata

    def read_entry(self, key_data):
        key_record = keyentry()
        local_index = 0
        num_components = self.convert_to_integer(key_data[local_index:local_index + 2])
        local_index += 2
        local_index, realm = self.read_str(key_data, local_index)
        key_record.realm = realm.decode()

        for component in range(num_components):
            local_index, principal = self.read_str(key_data, local_index)
            key_record.principal = principal.decode()

        local_index, name_type = self.read_bytes(key_data, local_index, 4)
        key_record.name_type = self.convert_to_integer(name_type)

        local_index, timestamp = self.read_bytes(key_data, local_index, 4)
        key_record.timestamp = self.convert_to_integer(timestamp)

        local_index, key_number = self.read_bytes(key_data, local_index, 1)
        key_record.kvno = self.convert_to_integer(key_number)

        local_index, encryption_type = self.read_bytes(key_data, local_index, 2)
        key_record.encryption_type = self.convert_to_integer(encryption_type)

        local_index, key_length = self.read_bytes(key_data, local_index, 2)
        converted_key_length = self.convert_to_integer(key_length)
        local_index, key_content = self.read_bytes(key_data, local_index, converted_key_length)
        key_record.key = key_content
        if len(key_data) - local_index >= 4:
            local_index, extended_kvno = self.read_bytes(key_data, local_index, 4)
            key_record.kvno_extended = self.convert_to_integer(extended_kvno)
            key_record.kvno = key_record.kvno_extended & 0xff

        return local_index, key_record

    def load(self, keytabfile: str) -> bool:
        self._keytabfile = keytabfile
        if not os.path.exists(keytabfile):
            return False
        index = 0
        filesize = os.stat(keytabfile).st_size
        with open(keytabfile, 'rb') as keyfile:
            whole_file = keyfile.read()

        magic_header = whole_file[index]
        index += 1
        if magic_header != 5:
            print("Not a keytab file")
            return False

        # 1 == native byte order for integer representations
        # 2 == big-endian byte order
        self.keytab_version = whole_file[index]
        index += 1

        while index < filesize - 2:
            record_size = self.convert_to_integer(whole_file[index:index + 4])
            index += 4
            add_index, key_entry = self.read_entry(whole_file[index:index + record_size])
            index += add_index
            self.key_entries.append(key_entry)

        return True

    def save(self, keytabfile: str = '') -> bool:
        newkeytab = ''
        if keytabfile == '':
            if self._keytabfile == '':
                return False
            else:
                newkeytab = self._keytabfile
        else:
            newkeytab = keytabfile

        with open(newkeytab, 'wb') as newfile:
            newfile.write(self.export())

            return True

        return False

    def entries(self) -> List[keyentry]:
        return self.key_entries

    def entry(self, keyid: int) -> keyentry:
        if keyid < len(self.entries()):
            return self.key_entries[keyid]

        return keyentry()

    def purge(self, keyid: int):
        if keyid < len(self.entries()):
            self.key_entries.remove(keyid)

    def export(self) -> bytes:
        export_data = b''
        for one_entry in self.entries():
            if one_entry.deleted is False:
                export_data = export_data + one_entry.export()

        return b'\x05\x02' + export_data


class principal_entry():
    def __init__(self):
        self.name_type = 0
        self._realm = str()
        self.components: List[str] = list()
        self._configuration_entry = False

    def spn(self) -> str:
        return '/'.join(self.components) + '@' + self.realm

    def name_type_name(self) -> str:
        if self.name_type in name_types:
            return name_types[self.name_type]

        return 'unknown-name-type'

    @property
    def realm(self) -> str:
        return self._realm

    @realm.setter
    def realm(self, new_realm: str):
        self._realm = new_realm

    @property
    def configuration_entry(self):
        return self._configuration_entry

    @configuration_entry.setter
    def configuration_entry(self, newvalue: bool):
        self._configuration_entry = newvalue
        if self._configuration_entry is True:
            self.realm = 'X-CACHECONF:'
            self.components[0] = 'krb5_ccache_conf_data'
        else:
            self.realm = str()
            self.components.remove('krb5_ccache_conf_data')

    def configuration_key(self) -> str:
        if self.configuration_entry is False:
            return str()
        if self.components[0] != 'krb5_ccache_conf_data':
            return str()
        if len(self.components) < 2:
            return str()

        return self.components[1]

    def configuration_domain(self) -> str:
        if self.configuration_entry is False:
            return str()
        if self.components[0] != 'krb5_ccache_conf_data':
            return str()
        if len(self.components) < 3:
            return str()

        return self.components[2]

    def export(self) -> bytes:
        retdata = self.name_type.to_bytes(4, 'big')
        retdata += len(self.components).to_bytes(4, 'big')
        retdata += len(self.realm).to_bytes(4, 'big')
        retdata += self.realm.encode()
        for one_component in self.components:
            retdata += len(one_component).to_bytes(4, 'big')
            retdata += one_component.encode()

        return retdata


class header_entry():
    def __init__(self):
        self.tag = 0
        self.tagdata = 0

    def tag_name(self) -> str:
        if self.tag in tag_types:
            return tag_types[self.tag]

        return str()

    def export(self) -> bytes:
        retdata = self.tag.to_bytes(2, 'big')
        retdata += len(self.tagdata).to_bytes(2, 'big')
        retdata += self.tagdata

        return retdata


class address_entry():
    def __init__(self):
        self.address_type = 0
        self.address = ''

    def export(self) -> bytes:
        retdata = self.address_type.to_bytes(2, 'big')
        retdata += len(self.address).to_bytes(4, 'big')
        retdata += self.address.encode()

        return retdata


class authdata_entry():
    def __init__(self):
        self.authdata_type = 0
        self.authdata = ''

    def export(self) -> bytes:
        retdata = self.authdata_type.to_bytes(2, 'big')
        retdata += len(self.authdata).to_bytes(4, 'big')
        retdata += self.authdata.encode()

        return retdata


class credential():
    def __init__(self):
        self.client_principal = principal_entry()
        self._server_principal = principal_entry()
        self.key_type = 0
        self.encryption_type = 0
        self.encryption_key = b''
        self.auth_time = 0
        self.start_time = 0
        self.end_time = 0
        self.renew_till = 0
        self.skey = 0
        self.ticket_flags = 0
        self.addresses: List(address_entry) = list()
        self.authdata: List(authdata_entry) = list()
        self.first_ticket = b''
        self.second_ticket = b''
        self.configuration_entry = False

    @property
    def server_principal(self) -> principal_entry:
        return self._server_principal

    @server_principal.setter
    def server_principal(self, new_entry: principal_entry):
        if new_entry.realm == 'X-CACHECONF:' and new_entry.name_type == 0:
            self.configuration_entry = True
        self._server_principal = new_entry

    def export(self) -> bytes:
        retdata = self.client_principal.export()
        retdata += self.server_principal.export()

        retdata += self.key_type.to_bytes(2, 'big')
        # retdata += self.encryption_type.to_bytes(2, 'big')
        retdata += len(self.encryption_key).to_bytes(4, 'big')
        retdata += self.encryption_key

        retdata += self.auth_time.to_bytes(4, 'big')
        retdata += self.start_time.to_bytes(4, 'big')
        retdata += self.end_time.to_bytes(4, 'big')
        retdata += self.renew_till.to_bytes(4, 'big')

        retdata += self.skey.to_bytes(1, 'big')
        retdata += self.ticket_flags.to_bytes(4, 'big')

        retdata += len(self.addresses).to_bytes(4, 'big')
        for one_address in self.addresses:
            retdata += one_address.export()

        retdata += len(self.authdata).to_bytes(4, 'big')
        for one_authdata in self.authdata:
            retdata += one_authdata.export()

        retdata += len(self.first_ticket).to_bytes(4, 'big')
        retdata += self.first_ticket

        retdata += len(self.second_ticket).to_bytes(4, 'big')
        retdata += self.second_ticket

        return retdata


class credentialcache():
    def __init__(self):
        self.magic_header = 5
        self.cc_version = 0
        self.headers: List[header_entry] = list()
        self.primary_principal = principal_entry()
        self.credential_entries: List[credential] = list()
        self._ccfile = str()

    def credentials(self, include_configuration: bool = False) -> List[credential]:
        if include_configuration:
            return self.credential_entries
        real_credentials = list()
        for one in self.credential_entries:
            if one.configuration_entry is False:
                real_credentials.append(one)

        return real_credentials

    def convert_to_integer(self, value) -> int:
        returning = int.from_bytes(value, "big")

        return returning

    def read_bytes(self, filedata, index, read_length) -> Tuple[int, bytes]:
        retdata = filedata[index:index + read_length]
        index += read_length

        return index, retdata

    def read_str(self, filedata, index, str_length: int = 4) -> Tuple[int, bytes]:
        length = self.convert_to_integer(filedata[index:index + str_length])
        index += str_length
        retdata = filedata[index:index + length]
        index += length

        return int(index), retdata

    def read_principal(self, filedata, index) -> Tuple[int, principal_entry]:
        the_principal = principal_entry()
        index, name_type = self.read_bytes(filedata, index, 4)
        the_principal.name_type = self.convert_to_integer(name_type)

        index, no_comp = self.read_bytes(filedata, index, 4)

        index, raw_realm = self.read_str(filedata, index)
        the_principal.realm = raw_realm.decode()

        for component in range(int.from_bytes(no_comp, "big")):
            index, raw_principal = self.read_str(filedata, index)
            the_principal.components.append(raw_principal.decode())

        return index, the_principal

    def read_addresses(self, filedata, index) -> Tuple[int, List[address_entry]]:
        address_list: List[address_entry] = list()
        index, raw_num_addresses = self.read_bytes(filedata, index, 4)
        num_addresses = int.from_bytes(raw_num_addresses, "big")
        for one_address in range(num_addresses):
            address = address_entry()
            index, raw_address_type = self.read_bytes(filedata, index, 2)
            index, raw_addressdata = self.read_str(filedata, index)
            address.address_type = raw_address_type
            address.address = raw_addressdata

            address_list.append(address)

        return index, address_list

    def read_authdata(self, filedata, index) -> Tuple[int, List[authdata_entry]]:
        authdata_list: List[authdata_entry] = list()
        index, raw_num_authdata = self.read_bytes(filedata, index, 4)
        num_authdata = int.from_bytes(raw_num_authdata, "big")
        for one_authdata in range(num_authdata):
            authdata = authdata_entry()
            index, raw_authdata_type = self.read_bytes(filedata, index, 2)
            index, raw_authdata = self.read_str(filedata, index)
            authdata.authdata_type = raw_authdata_type
            authdata.authdata = raw_authdata

            authdata_list.append(authdata)

        return index, authdata_list

    def load(self, ccfile: str) -> bool:
        self._ccfile = ccfile
        if not os.path.exists(ccfile):
            return False
        index = 0
        with open(ccfile, 'rb') as ccfilehandle:
            whole_file = ccfilehandle.read()

        magic_header = whole_file[index:index + 2]
        index += 2
        if magic_header != b'\x05\x04':
            print("Not a supported keytab credential cache file")
            return False

        self.magic_header = int(magic_header[0])
        self.cc_version = int(magic_header[1])
        # 1 == native byte order for integer representations
        # 2 == big-endian byte order
        index, raw_length = self.read_bytes(whole_file, index, 2)
        header_length = int.from_bytes(raw_length, "big")
        header_index = 0

        while header_index < header_length:
            one_header = header_entry()

            index, tag = self.read_bytes(whole_file, index, 2)
            one_header.tag = int.from_bytes(tag, "big")
            header_index += 2

            index, raw_length = self.read_bytes(whole_file, index, 2)
            tag_length = int.from_bytes(raw_length, "big")
            header_index += 2
            index, tag_data = self.read_bytes(whole_file, index, tag_length)
            one_header.tagdata = tag_data
            header_index += tag_length

            self.headers.append(one_header)

        # Primary principal
        index, self.primary_principal = self.read_principal(whole_file, index)

        while index < len(whole_file) - 2:
            one_credential = credential()
            # Client principal
            index, client_principal = self.read_principal(whole_file, index)
            one_credential.client_principal = client_principal

            # Server principal
            index, server_principal = self.read_principal(whole_file, index)
            one_credential.server_principal = server_principal

            # Key block
            index, key_type = self.read_bytes(whole_file, index, 2)
            one_credential.key_type = int.from_bytes(key_type, "big")
            # if self.magic_header == b'\x05\x03':
            index, encryption_type = self.read_bytes(whole_file, index, 2)
            one_credential.encryption_type = int.from_bytes(encryption_type, "big")

            # Encryption key
            index, raw_key_length = self.read_bytes(whole_file, index, 2)
            key_length = int.from_bytes(raw_key_length, "big")
            index, encryption_key = self.read_bytes(whole_file, index, key_length)
            one_credential.encryption_key = encryption_key

            # Times
            index, auth_time = self.read_bytes(whole_file, index, 4)
            one_credential.auth_time = int.from_bytes(auth_time, "big")
            index, start_time = self.read_bytes(whole_file, index, 4)
            one_credential.start_time = int.from_bytes(start_time, "big")
            index, end_time = self.read_bytes(whole_file, index, 4)
            one_credential.end_time = int.from_bytes(end_time, "big")
            index, renew_till = self.read_bytes(whole_file, index, 4)
            one_credential.renew_till = int.from_bytes(renew_till, "big")

            # Skey
            index, raw_skey = self.read_bytes(whole_file, index, 1)
            one_credential.skey = int.from_bytes(raw_skey, "big")

            # Ticket flags
            index, raw_ticket_flags = self.read_bytes(whole_file, index, 4)
            one_credential.ticket_flags = int.from_bytes(raw_ticket_flags, "big")

            # Addresses
            index, address_data = self.read_addresses(whole_file, index)
            one_credential.addresses = address_data

            # Authdata
            index, authdata_data = self.read_authdata(whole_file, index)
            one_credential.authdata = authdata_data

            # First ticket
            index, ticket_one = self.read_str(whole_file, index)
            if one_credential.server_principal.realm == 'X-CACHECONF:':
                one_credential.first_ticket = ticket_one
            else:
                one_credential.first_ticket = ticket_one
                # one, two, three, four, five, six = parse(ticket_one)
                # one_credential.first_ticket = five

            # Second ticket
            index, second_ticket = self.read_bytes(whole_file, index, 4)
            self.credential_entries.append(one_credential)

        return True

    def export(self) -> bytes:
        retdata = self.magic_header.to_bytes(1, 'big')
        retdata += self.cc_version.to_bytes(1, 'big')

        headerdata = b''
        for one_header in self.headers:
            headerdata += one_header.export()

        retdata += len(headerdata).to_bytes(2, 'big')
        retdata += headerdata

        retdata += self.primary_principal.export()

        for one_credential in self.credentials(include_configuration=True):
            retdata += one_credential.export()

        return retdata

    def save(self, ccfile: str = '') -> bool:
        newcc = ''
        if ccfile == '':
            if self._ccfile == '':
                return False
            else:
                newcc = self._ccfile
        else:
            newcc = ccfile

        with open(newcc, 'wb') as newfile:
            newfile.write(self.export())

            return True

        return False
