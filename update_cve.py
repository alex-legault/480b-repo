from contextlib import contextmanager
import time
import psycopg2
from psycopg2.extras import DictCursor
import pandas as pd
import re
import os
import shutil

res_dir = 'results'

regex_cve = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
regex_cwe = re.compile(r"(CWE-[\d]{1,4})", re.IGNORECASE)
regex_nvd = re.compile(r"(NVD .+)", re.IGNORECASE)
regex_sql_inj = re.compile(r"sql ?injection", re.IGNORECASE)

regexes = [regex_cve, regex_cwe, regex_nvd]

con = psycopg2.connect(database="sengproject3", user="postgres", password="psqlpsql")

print("Database opened successfully")

cve_list = pd.read_csv(os.path.join("assets", "cve_related_problems.csv"), sep="\t")
# Bug Fix -> Rename CVE to cve_data
cve_list.rename(columns={'CVE' : 'cve_data', "Problem" : 'cwe_group'}, inplace=True)

# Bug Fix -> Add published_date,severity,impact_score -> This Data wasn't available previously
cvss_list = pd.read_csv(os.path.join("assets", "cve_cvss_scores.csv"), sep="\t")

# Bug Fix -> Rename Columns - CVE, "Published Date", "Impact Score"
cvss_list.rename(columns={'CVE' : 'cve_data', 'Published Date' : 'published_date', "Impact Score" : "impact_score"}, inplace=True)

@contextmanager
def timed_cursor():
    start_time = time.time()
    yield con.cursor(cursor_factory=DictCursor)
    print("--- %s seconds ---" % (time.time() - start_time))


def get_cve(row):
    rv = list()
    for regex in regexes:
        row_msg = row['msg']
        rv.extend(regex.findall(row_msg))
    if not rv and regex_sql_inj.search(row['msg']):
        rv.append("sql_injection")
    return rv


def copy_cwe(row):
    if not isinstance(row['cve_data'], str):
        return row['cwe_group']
    if 'CWE' in row['cve_data']:
        return row['cve_data']
    return row['cwe_group']


def create_statistics(df, lang):
    cwe_counts = df['cwe_group'].value_counts()
    cwe_counts.to_csv(os.path.join(res_dir, f'count_cwe_groups_{lang}.csv'), header=False)

    severity_counts = df['severity'].value_counts()
    severity_counts.to_csv(os.path.join(res_dir, f'count_severity_{lang}.csv'), header=False)

    avg_impacts = df['impact_score'].describe()
    avg_impacts.to_csv(os.path.join(res_dir, f'stat_impact_score_{lang}.csv'), header=False)

    # Bug Fix -> "Array must be all same time zone"
    df['commit_date'] = pd.to_datetime(df['commit_date'], utc=True)

    stat_yearly = df[['commit_date']]
    stat_yearly = stat_yearly.groupby(stat_yearly.commit_date.dt.year).count()
    stat_yearly.to_csv(os.path.join(res_dir, f'fixes_per_year_{lang}.csv'), header=False)

    cwe_group_year = df[['commit_date', "cwe_group"]]
    cwe_group_year = cwe_group_year.groupby([cwe_group_year.commit_date.dt.year, 'cwe_group']).count()
    cwe_group_year.to_csv(os.path.join(res_dir, f'count_cwe_groups_by_year_{lang}.csv'), header=False)

def run_on(lang):
    df = None
    with timed_cursor() as cur:
        query = f"SELECT * FROM cve_revs_{lang}"
        df = pd.read_sql_query(query, con=con)
        # print(df)
    if df is None:
        print("Query failed")
        return

    # Extract CVE number
    df['cve_data'] = df.apply(lambda row: get_cve(row), axis=1)

    # Explode revisions with multiple CVE
    df = df.explode("cve_data")

    # CVEs should be all uppered
    df['cve_data'] = df['cve_data'].str.upper()

    # Clean unnecessary fields
    del df['msg']

    # Bug Fix -> There is no column named cve
    #del df['cve']

    # Drop false rows
    df = df[df.cve_data.notnull()]

    # JOIN the cve_list to the data
    df = df.merge(cve_list, on="cve_data", how="left")

    # Bug Fix -> Add published_date,severity,impact_score
    df = pd.merge(df, cvss_list[['cve_data', 'published_date', 'severity', 'impact_score']], on='cve_data', how='left')

    # Copy CWE if CWE was used in commit message
    df['cwe_group'] = df.apply(lambda row: copy_cwe(row), axis=1)

    # Save csv
    df.to_csv(os.path.join(res_dir, rf'result_{lang}.csv'))

    create_statistics(df, lang)


def select_random_rows(table, limit):
    sql = f"select * from {table} order by random() limit {limit};"
    with timed_cursor() as cur:
        df = pd.read_sql_query(sql, con=con)
        with open(os.path.join(res_dir, f"sample_from_{table}.txt"), 'w') as f:
            for rec_index, rec in df.iterrows():
                f.write(f'------- commit message {rec_index} starts -------\n')
                f.write(rec['msg'])
                f.write('\n------- commit message ends -------\n')


if __name__ == '__main__':
    if os.path.exists(res_dir):
        shutil.rmtree(res_dir)
    os.makedirs(res_dir)
    run_on("js")
    run_on("py")

    # select_random_rows("cve_revs_py", 348)
    # select_random_rows("cve_revs_js", 352)
