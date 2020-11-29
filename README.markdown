Enpass 6 Encryption Details
===========================

A proof-of-concept to recover passwords from the encrypted Enpass database. Unfortunately the Enpass developers were not willing to share any information on the [encryption details](https://discussion.enpass.io/index.php?/topic/4446-enpass-6-encryption-details/). Luckily the community was able to make [progress](https://github.com/hazcod/enpass-cli/issues/16) and reverse engineer the database layout and encryption.

Contents
--------

  * `vault/vault.enpassdb`: sample Enpass vault with known contents and master password
  * `vault/vault.json`: the corresponding Enpass metadata for the sake of completeness
  * `vault/vault.sqlite`: the decrypted sqlite for easier inspection
  * `enpass-cli-v6.py`: python script to access the passwords inside the Enpass vault


Vault database structure
------------------------

### Tables

  * `Identity`
  * `attachment`
  * `category`
  * `custom_icon`
  * `folder`
  * `folder_items`
  * `item`
  * `itemfield`
  * `password_history`
  * `preferences`
  * `share_info`
  * `sqlite_sequence`
  * `template`
  * `vault_info`

### Schema

```
CREATE TABLE Identity(ID INTEGER PRIMARY KEY AUTOINCREMENT CHECK (ID=1), Version INTEGER, Signature TEXT, Sync_UUID TEXT, Hash TEXT, Info BLOB);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE vault_info(ID INTEGER PRIMARY KEY AUTOINCREMENT,vault_uuid TEXT UNIQUE NOT NULL,mp BLOB,keyfile BLOB,key BLOB,UNIQUE(vault_uuid) ON CONFLICT REPLACE);
CREATE TABLE item(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT UNIQUE NOT NULL,created_at INTEGER,meta_updated_at INTEGER,field_updated_at INTEGER,title TEXT,subtitle TEXT,note TEXT,icon TEXT,favorite INTEGER DEFAULT 0,trashed INTEGER DEFAULT 0,archived INTEGER DEFAULT 0,deleted INTEGER DEFAULT 0,auto_submit INTEGER DEFAULT 1,form_data TEXT DEFAULT '',category TEXT,template TEXT,wearable INTEGER DEFAULT 0,usage_count INTEGER DEFAULT 0,last_used INTEGER,key BLOB,extra TEXT DEFAULT '',updated_at INTEGER DEFAULT 0);
CREATE TABLE itemfield(ID INTEGER PRIMARY KEY AUTOINCREMENT,item_uuid TEXT,item_field_uid INTEGER,label TEXT,value TEXT,deleted INTEGER,sensitive INTEGER,historical INTEGER,type TEXT,form_id TEXT,updated_at INTEGER,value_updated_at INTEGER,orde INTEGER,wearable INTEGER,history TEXT,initial TEXT,hash TEXT,strength INTEGER DEFAULT -1,algo_version INTEGER DEFAULT 0,expiry INTEGER DEFAULT 0,excluded INTEGER DEFAULT 0,pwned_check_time INTEGER DEFAULT 0,extra TEXT DEFAULT '',UNIQUE(item_uuid,item_field_uid) ON CONFLICT REPLACE);
CREATE TABLE folder(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT UNIQUE NOT NULL,title TEXT,icon TEXT,updated_at INTEGER,deleted INTEGER,parent_uuid TEXT,extra TEXT DEFAULT '');
CREATE TABLE folder_items(ID INTEGER PRIMARY KEY AUTOINCREMENT,folder_uuid TEXT,item_uuid TEXT,updated_at INTEGER,deleted INTEGER,extra TEXT DEFAULT '',UNIQUE(folder_uuid, item_uuid) ON CONFLICT REPLACE);
CREATE TABLE attachment(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT UNIQUE NOT NULL,item_uuid TEXT,name TEXT,size INTEGER,orde INTEGER,mime TEXT,updated_at INTEGER,created_at INTEGER,deleted INTEGER,internal INTEGER,password blob,data blob,extra TEXT DEFAULT '');
CREATE TABLE custom_icon(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT NOT NULL,data BLOB,updated_at INTEGER,deleted INTEGER,type INTEGER,extra TEXT, UNIQUE(uuid) ON CONFLICT REPLACE);
CREATE TABLE preferences(ID INTEGER PRIMARY KEY AUTOINCREMENT,vault TEXT,key TEXT,value BLOB,UNIQUE(vault,key) ON CONFLICT REPLACE);
CREATE TABLE share_info(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT UNIQUE NOT NULL,title TEXT,value TEXT,updated_at INTEGER,deleted INTEGER);
CREATE TABLE template(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT UNIQUE NOT NULL,title TEXT,cateogry_uuid TEXT,icon TEXT,field_json TEXT,updated_at INTEGER,deleted INTEGER,extra TEXT DEFAULT '');
CREATE TABLE category(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT,title TEXT,icon TEXT,updated_at INTEGER,deleted INTEGER,extra TEXT DEFAULT '');
CREATE TABLE password_history(ID INTEGER PRIMARY KEY AUTOINCREMENT,uuid TEXT UNIQUE NOT NULL,password BLOB,created_at INTEGER,domain TEXT,deleted INTEGER,extra TEXT);
```


Sample Vault
------------

With 11 items and passwords of varying length.

| id | title  | cleartext = password              | hex(cipher) = hex(itemfield['value'])                                                              |
|----|--------|-----------------------------------|----------------------------------------------------------------------------------------------------|
|  1 | item1  | 1                                 | 7385c1be632c8502f982b461702a9bf955                                                                 |
|  2 | item2  | 12                                | 705275f0a16e089062a3090af7a99925b7a0                                                               |
|  3 | item3  | 123                               | f01d5161cc32d8ef2eb1d639c10c9c9a1974f9                                                             |
|  4 | item14 | 12345678901234                    | 59103da1b4df3b477750a9b81026d16e317e42f86c94720513e33eecbc3e                                       |
|  5 | item15 | 123456789012345                   | 9875c2944f18f7ebbe34e12d61d0de4a1750bea540bd10570f875a446c34da                                     |
|  6 | item16 | 1234567890123456                  | cc9851b3ac19a0a2f3274a7b08bdf41053b4148dff40318f19717e117d5c31e3                                   |
|  7 | item17 | 12345678901234567                 | a59f45c847e88905950b81779f56d77f135c6d8fa370ce5342b458d60d791c2969                                 |
|  8 | item18 | 123456789012345678                | 9e6d6e30ad5b24d597ac2a0d6b41205cd99769a6397db9d4d35cf6bbc6e4e596f746                               |
|  9 | item31 | 1234567890123456789012345678901   | 62090ca9ec203f22ce4e219852373d599c184ed98f6dded7e96592ed502df983ab7e0000b35d916b202ac1f9b845b3     |
| 10 | item32 | 12345678901234567890123456789012  | f8c743e369e94c48d32382fde901892f5abcac6eb7b1b4590158a0c509ab4635f19e102a9bd001c5c05c92fd4e15ca63   |
| 11 | item33 | 123456789012345678901234567890123 | 45c353521c775bf11264b35bd0be351e3a67b486bd75fd778036e060a31595603470dbb862f617c5f9a0689efab21546fc |
