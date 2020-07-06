import requests
import sys
import json
import central_oauth

# Set your credentials.
client_id = ""
client_secret = ""
vt_api = ""

# Get the credentials you need
jwt, tenant_id, tenant_type, data_region = central_oauth.Authenticate.auth(client_id, client_secret)


def sophos_central(sha, comment):
    # run the vt_check function
    vt = vt_check(sha)
    # During the bootcamp session we got to here. This doesn't validate against a SOPHOS Result.
    # What we'll do is do another if statement so if reponse_code is 1 and the key scans/Sophos/detected
    # exists we'll then tell the user it's known bad else, we'll pass and block it. 
    if vt['response_code'] == 1:
        # We'll add an additional check here to see if SOPHOS Makes the detection or not.
        if vt['scans']['Sophos']['detected']:
            # Notify the user
            print ("SHA256 already known bad, not adding to sophos central")
        else:
            # Publish the SHA to Central if it's not in the detected category.
            # Instead of copy and pasting between this else block and the one below
            # It would be better to use a decorator or a function if you're interested
            # read about this in the python docs and try and make this more optimised.
            u = f"{data_region}/endpoint/v1/settings/blocked-items"
            b = {
            "type": "sha256",
            "properties": {
                "sha256": f"{sha}"
            },
            "comment": f"{comment}"
            }
            h = {
                'Authorization': f'Bearer {jwt}',
                'X-Tenant-ID': f'{tenant_id}'
            }

            r = requests.post(u, headers=h, json=b)

            print("Succesfully added to sophos central")
    else:
        u = f"{data_region}/endpoint/v1/settings/blocked-items"
        b = {
        "type": "sha256",
        "properties": {
            "sha256": f"{sha}"
        },
        "comment": f"{comment}"
        }
        h = {
            'Authorization': f'Bearer {jwt}',
            'X-Tenant-ID': f'{tenant_id}'
        }

        r = requests.post(u, headers=h, json=b)

        print("Succesfully added to sophos central")


def vt_check(sha):
    u = 'https://www.virustotal.com/vtapi/v2/file/report'

    p = {'apikey': f'{vt_api}', 'resource': f'{sha}'}

    r = requests.get(u, params=p)

    if r.status_code == 200:
        j = json.loads(r.text)
        return j

if __name__ == "__main__":
    # This gets the commandline arguments [0] is the file name
    # sha = sys.argv[1]
    # comment = sys.argv[2]
    # Not done during the session but we should validate this or use the option parser function
    # for simplicity we'll just use an if statement and check to see if the length is 3 but if 
    # you're interested in learning more after the bootcamp session please read the python docs about option parser
    if len(sys.argv) == 3:
        sha = sys.argv[1]
        comment = sys.argv[2] 
        print(f"Searchin for SHA {sha}")
        sophos_central(sha, comment)
    else:
        print("Missing required arguments app.py SHA COMMENT")
