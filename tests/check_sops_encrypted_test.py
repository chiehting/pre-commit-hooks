# test_check_sops_encrypted.py
import pytest
from pre_commit_hooks.check_sops_encrypted import main

FILE_CONTENTS = {
    "bad.yaml": "foo: bar\n",
    "good.yaml": """
foo: ENC[AES256_GCM,data:3mHv,iv:JqRbg5JxyTYSOAEtqyGvbippnyx+qCzGPwYUlW/A5sQ=,tag:5IjXkoYwv2uRnk8B6lVqNA==,type:str]
sops:
  lastmodified: "2025-09-24T07:46:47Z"
  mac: ENC[AES256_GCM,data:+/H5ZIY6=,iv:NApXh6Ll=,tag:X48vM=,type:str]
  pgp:
    - created_at: "2025-09-24T07:46:47Z"
      enc: |-
        -----BEGIN PGP MESSAGE-----
        Ht+Zk2Dn3vTGwA==
        =CT+E
        -----END PGP MESSAGE-----
      fp: A0515DB2446
  unencrypted_suffix: _unencrypted
  version: 3.10.2
""",
    "bad.json": """
{
  "foo": "bar"
}
""",
    "good.json": """
{
  "foo": "ENC[AES256_GCM,data:SlFv,iv:m8SRlHFmCE2DFTfJ3iDs+njh1/PtzcuJctp5osAmmvg=,tag:tu+jOneTtZfFE14itsVYqQ==,type:str]",
  "sops": {
    "lastmodified": "2025-09-24T07:46:25Z",
    "mac": "ENC[AES256_GCM,data:mS1JolKS89Ops=,iv:xQrwr7E=,tag:0pa65ALg==,type:str]",
    "pgp": [
      {
        "created_at": "2025-09-24T07:46:25Z",
        "enc": "-----BEGIN PGP MESSAGE-----\\n\\nhF4SBnF1IQ==\\n=RXKC\\n-----END PGP MESSAGE-----",
        "fp": "A055C9F0446"
      }
    ],
    "unencrypted_suffix": "_unencrypted",
    "version": "3.10.2"
  }
}
""",
    "good.env": """
foo=ENC[AES256_GCM,data:lS5P,iv:zsNNOJu1xTGHLFjZ7znw7HqZSLG4FrEc3xNRA4yrzYM=,tag:iCA34MW3RwgCJMEqfRZZKg==,type:str]
sops_lastmodified=2025-09-24T08:36:52Z
sops_mac=ENC[AES256_GCM,data:wR0uns5EcQ=,iv:ietELPZg3Whet4Ik=,tag:3gbP3kfRjphrDLL7EN4GXg==,type:str]
sops_pgp__list_0__map_created_at=2025-09-24T08:36:52Z
sops_pgp__list_0__map_enc=-----BEGIN PGP MESSAGE-----\\n\\nhF4DXnLW9CV3HL0KOg==\\n=2CwZ\\n-----END PGP MESSAGE-----
sops_pgp__list_0__map_fp=A0552446
sops_unencrypted_suffix=_unencrypted
sops_version=3.10.2
""",
    "bad.env": """
foo=bar
"""
}

@pytest.mark.parametrize(
    "filename,content,expected",
    [
        ("bad.yaml", FILE_CONTENTS["bad.yaml"], 1),
        ("good.yaml", FILE_CONTENTS["good.yaml"], 0),
        ("bad.json", FILE_CONTENTS["bad.json"], 1),
        ("good.json", FILE_CONTENTS["good.json"], 0),
        ("good.env", FILE_CONTENTS["good.env"], 0),
        ("bad.env", FILE_CONTENTS["bad.env"], 1),
    ],
)
def test_sops_encrypted(tmpdir, filename, content, expected):
    path = tmpdir.join(filename)
    path.write(content)
    args = (('--silent', str(path)) if expected == 1 else (str(path),))
    assert main(args) == expected