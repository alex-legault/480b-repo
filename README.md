__Overview__

Running on Windows 10, using GitBash/PowerShell to run these commands. If a command doesn't work on GitBash, try PowerShell. If that doesn't work, cry

You may need to install some packages if you are running some scripts. More here: https://pip.pypa.io/en/stable/getting-started/

__Steps:__

1) create a database

```createdb -U postgres sengproject```

2) load sql. this means loading all 22gb into the database. has to be done on git bash (for me). load.sql and all .gz files have to be in same directory and where git bash pwd is. 

```psql -U postgres -f load_no_index.sql sengproject```


3) create cve_revs tables. this means running all ```create_table_cve_yaddayadda.sql``` files. should be three of them, similar command as above but change file


4) run ```cve_manager.py```. this should download a bunch of NVD .zips and then populate the assets folder with three csv files

```py .\cve_manager.py -d -p -csv -i .\nvd\ -o .\assets\```

5) run ```update_cve.py```. __this file will probably fail because it is set to connect to my local data (sengproject3)__. this execution is what populates our results folder. __if you want to skip the database business you can follow the steps after this one__

```py .\update_cve.py```

6) working on this part. i am adapting the original scripts and 0xsuid's scripts to work with this repo. so far only have ```0xsuid_stat1.py``` done

```py .\0xsuid_stat.py```


__References:__

0xsuid repo: https://github.com/0xsuid/msr-security-awareness \
Gabor et al. scripts: https://zenodo.org/record/3699486 \
Gabor et al. paper: https://arxiv.org/abs/2006.13652