#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Backup/create encrypted/not encrypted dumps from HashiCorps's Vault secrets to json/yaml dumps
# Populate Vault from json/yaml dump
#
# ENV variables:
# VAULT_ADDR: for example: 'http://vault.vault.svc.cluster.local:8200' for k8s cluster
# ROLE_ID:  RoleID for AppRole auth
# SECRET_ID:  SecretID for AppRole auth
# VAULT_PREFIX: for example 'jenkins', defaults to '/'
# ENCRYPTION_KEY: encryption key(used by Fernet library) to encrypt your secrets dump (can be generated with e.g. `dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64`)
# VAULT_SECRET_MOUNT: vault secret mount name, defaults to 'secret'
#
# Copyright (c) 2021 Igor Zhivilo <igor.zhivilo@gmail.com>
# Licensed under the MIT License
import json
import os

import click
import hvac
from cryptography.fernet import Fernet

VAULT_TOKEN = os.environ.get('VAULT_TOKEN', '')
VAULT_ADDR = os.environ.get('VAULT_ADDR')
ROLE_ID = os.environ.get('ROLE_ID')
SECRET_ID = os.environ.get('SECRET_ID')
VAULT_SECRET_MOUNT = os.environ.get('VAULT_SECRET_MOUNT', 'secret')
VAULT_PREFIX = os.environ.get('VAULT_PREFIX', '/')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

vault_instance = None


class VaultHandler:
    def __init__(self, url, role_id, secret_id, path, enc_key, vault_secret_mount, vault_token):
        self.url = url
        self.role_id = role_id
        self.secret_id = secret_id
        self.path = path
        self.enc_key = enc_key
        self.vault_token = vault_token
        self.vault_secret_mount = vault_secret_mount
        self.client = hvac.Client(url=self.url)

        if VAULT_TOKEN != '':
            self.client.token = self.vault_token
        else:
            self.client.auth.approle.login(
                role_id=self.role_id,
                secret_id=self.secret_id,
            )

        if not self.client.is_authenticated():
            raise Exception('Vault authentication error!')

    def get_secrets_list(self, nested_path=None):
        top_level_secrets_list_response = self.client.secrets.kv.v2.list_secrets(
            mount_point=self.vault_secret_mount,
            path=nested_path if nested_path else '{}'.format(self.path),
        )

        secrets_list_response = []

        for key in top_level_secrets_list_response['data']['keys']:
            nested_key = '{}{}'.format(nested_path, key) if nested_path else key
            if key.endswith("/"):
                nested = self.get_secrets_list(nested_path=nested_key)
                for nested_key in nested:
                    secrets_list_response.append(nested_key)
            else:
                secrets_list_response.append(nested_key)

        return secrets_list_response

    def print_all_secrets_with_metadata(self):
        for key in self.get_secrets_list():
            print('\nKey is: {}'.format(key))
            secret_response = self.get_secret(key)
            print(secret_response)

    def _secrets_to_dict(self):
        secrets_dict = {}
        for key in self.get_secrets_list():
            secret_response = self.get_secret(key)

            secret_data = {}
            for k in secret_response['data']['data'].keys():
                secret_data = secret_response['data']['data'].copy()

            secrets_dict[key] = secret_data
        return secrets_dict

    def get_secret(self, key):
        return self.client.secrets.kv.v2.read_secret(mount_point=self.vault_secret_mount, path='{}/{}'.format(self.path, key))

    def print_secrets_nicely(self, secrets_dict={}):
        if not secrets_dict:
            secrets_dict = self._secrets_to_dict()
        for secret_name, secret in secrets_dict.items():
            print('\n{}'.format(secret_name))
            for attr_name, attr in secret.items():
                print(attr_name, ':', attr)

    def dump_all_secrets(self, dump_path):
        secrets_dict = self._secrets_to_dict()
        self._encrypt_dump(secrets_dict, dump_path)

    def _encrypt_dump(self, secrets_dict, dump_path):
        f = Fernet(self.enc_key)
        secrets_dict_byte = json.dumps(secrets_dict).encode('utf-8')
        encrypted_data = f.encrypt(secrets_dict_byte)
        with open(dump_path, 'wb') as file:
            file.write(encrypted_data)

    def _decrypt_dump(self, path_to_dump):
        f = Fernet(self.enc_key)
        with open(path_to_dump, 'rb') as file:
            file_data = file.read()
        decrypted_data = f.decrypt(file_data).decode('utf-8')
        return json.loads(decrypted_data)

    def print_secrets_from_encrypted_dump(self, path_to_dump):
        decrypted_data = self._decrypt_dump(path_to_dump)
        self.print_secrets_nicely(decrypted_data)

    def _populate_vault_prefix_from_dict(self, secrets_dict, vault_prefix_to_populate):
        for key in secrets_dict:
            self.client.secrets.kv.v2.create_or_update_secret(
                mount_point=self.vault_secret_mount,
                path='{}/{}'.format(vault_prefix_to_populate, key),
                secret=secrets_dict[key],
            )

    def populate_vault_from_dump(self, vault_prefix_to_populate, path_to_dump):
        secrets_dict = self._decrypt_dump(path_to_dump)
        self._populate_vault_prefix_from_dict(
            secrets_dict, vault_prefix_to_populate,
        )


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    group_commands = ['print', 'print-dump', 'dump', 'populate']
    """
    VaultHandler is a command line tool that helps dump/populate secrets of HashiCorp's Vault
    """

    if ctx.invoked_subcommand is None:
        click.echo('Specify one of the commands below')
        print(*group_commands, sep='\n')


@main.command('print')
@click.pass_context
def print_secrets(ctx):
    """
    Print secrets nicely.
    """
    vault_instance.print_secrets_nicely()


@main.command('print-dump')
@click.pass_context
@click.option(
    '--dump_path', '-dp',
    type=str,
    default='vault_secrets.enc',
    help='Path/name of dump with secrets',
)
def print_dump(ctx, dump_path):
    """
    Print secrets from encrypted dump.
    """
    vault_instance.print_secrets_from_encrypted_dump(dump_path)


@main.command('dump')
@click.pass_context
@click.option(
    '--dump_path', '-dp',
    type=str,
    default='vault_secrets.enc',
    help='Path/name of dump with secrets',
)
def dump_secrets(ctx, dump_path):
    """
    Dump secrets from Vault.
    """
    vault_instance.dump_all_secrets(dump_path)


@main.command('populate')
@click.pass_context
@click.option(
    '--vault_prefix', '-vp',
    type=str,
    required=True,
    help="Vault's prefix to populate from secrets dump",
)
@click.option(
    '--dump_path', '-dp',
    type=str,
    default='vault_secrets.enc',
    help='Path to dump with secrets',
)
def populate_vault_prefix(ctx, vault_prefix, dump_path):
    """
    Populate Vault prefix from dump with secrets.
    """
    vault_instance.populate_vault_from_dump(vault_prefix, dump_path)


# pylint:disable=no-value-for-parameter
if __name__ == '__main__':
    vault_instance = VaultHandler(
        VAULT_ADDR, ROLE_ID, SECRET_ID,
        VAULT_PREFIX, ENCRYPTION_KEY,
        VAULT_SECRET_MOUNT, VAULT_TOKEN,
    )
    main(obj={})
