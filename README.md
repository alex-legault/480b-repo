1) createdb: 'createdb -U postgres sengproject'
2) load sql. this means loading all 22gb into the database. has to be done on git bash (for me). load.sql and all .gz files have to be in same directory and where git bash pwd is. 'psql -U postgres -f load_no_index.sql sengproject'
3) create cve_revs tables. this means running all create_table_cve_yaddayadda.sql files. should be three of them, similar command as above but change file
4) run 'py .\cve_manager.py -d -p -csv -i .\nvd\ -o .\assets\'. this should download a bunch of NVD .zips and then populate the assets folder with three csv files
5) run update_cve.py