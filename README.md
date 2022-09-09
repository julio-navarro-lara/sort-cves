# sort-cves
A simple Python script to sort a set of CVEs by CVSSv3 score.

You just need to provide a list of CVE IDs separated by commas and the script will connect to the NVD database to check the CVSSv3 score and return the CVEs sorted from higher to lower score and, for those having the same score, from more to less recent publication date. 

I implemented some random delay to avoid using NVD API key, but feel free to reduce it if you want it faster.

Usage:

```
python3 sort_cves.py "<CVE list>"
```

It will trim the spaces and remove duplicates for you, so no worries about being neat.

Example:

![image](https://user-images.githubusercontent.com/70337782/189331273-654cb356-1820-4fd4-9da7-9974e374a898.png)
