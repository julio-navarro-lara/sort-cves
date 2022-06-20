# sort-cves
A simple Python script to sort a set of CVEs by CVSSv3 score.

You just need to provide a list of CVE IDs separated by commas and the script will connect to the NVD database to check the CVSSv3 score and return the CVEs sorted from higher to lower score. 

I implemented some random delay to avoid using NVD API key, but feel free to reduce it if you want it faster.

Usage:

```
python3 sort_cves.py "<CVE list>"
```

It will trim the spaces and remove duplicates for you, so no worries about being neat.

Example:
![Captura sort cve](https://user-images.githubusercontent.com/70337782/174626804-6b4ada9f-334d-4ac0-8cee-1867d247da79.PNG)
