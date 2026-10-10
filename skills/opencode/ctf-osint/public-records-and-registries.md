# OSINT - Public records, registries, and municipal open data

## Municipal open-data (Socrata) record queries for permits and filings

**Trigger:** The flag format asks for an official record identifier -- a 9-digit permit or job filing number, a business registration, a license number -- and the only handout is a street-scene photo or a rough address.

Do not try to read the building number off the facade; scaffolding and angled signage make it fragile, and you would have to verify it anyway. Read only the reliable anchors (green street-name signs, cross streets) to fix the jurisdiction and street, then go straight to that jurisdiction's open-data portal and let the structured query identify the building. NYC publishes DOB Job Application Filings as a Socrata resource at https://data.cityofnewyork.us/resource/ic3t-wcy2.json, which supports SQL-ish `$where` filtering and `$limit`. Filter server-side on the coarse facts you trust (borough plus a street-name substring), then post-filter locally with jq on the fields the dataset stores inconsistently -- `street_name` carries irregular internal whitespace, so collapse spaces before comparing to reject near-misses like EAST 25 STREET. Regex the `job_description` field against the challenge prompt's own wording (a prompt that says "3rd and 4th floor renovation" is quoting the filing text). The same shape applies to other jurisdictional identifiers: local transit-stop names come from the transport authority's published stop list plus community aggregators, and US federal work has SAM.gov, USAspending, EDGAR, the FAA aircraft registry and the FCC license database. LA Open Data, SF DataSF and the Chicago Data Portal all run the same Socrata API surface.

```bash
curl -sG 'https://data.cityofnewyork.us/resource/ic3t-wcy2.json' \
  --data-urlencode '$limit=50000' \
  --data-urlencode '$where=borough="MANHATTAN" AND upper(street_name) like "%25 STREET%"' \
| jq -r '.[] |
    select((.street_name|ascii_upcase|gsub(" ";""))=="WEST25STREET") |
    select((.job_description // "") | test("3rd and 4th|third and fourth"; "i")) |
    [.job__, .house__, .street_name, .owner_s_business_name, .job_description] | @tsv'
```

Source: https://cybersecurityelite.com/ctf-writeups/tracebash-ctf-2026-osint-writeup/
