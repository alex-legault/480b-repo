import pandas as pd
import matplotlib.pyplot as plt

# EDITED FILE PATHS
js_result_csv = pd.read_csv('result_js.csv').dropna(subset=['published_date'])
py_result_csv = pd.read_csv('result_py.csv').dropna(subset=['published_date'])

js_result_csv[['published_date','commit_date']] = js_result_csv[['published_date','commit_date']].apply(pd.to_datetime,utc=True)
js_result_csv['js_delta'] = ((js_result_csv['commit_date'] - js_result_csv['published_date']).dt.days).apply(lambda val: val if val>0 else 0)

# ADDED DROPPING OF 'Unnamed: 0' COLUMN - DON'T KNOW WHY IT'S THERE
js_stat_1 = js_result_csv.query('js_delta >= 0').drop(columns=['impact_score', 'Unnamed: 0']).groupby(js_result_csv['commit_date'].dt.year).agg('mean')

py_result_csv[['published_date','commit_date']] = py_result_csv[['published_date','commit_date']].apply(pd.to_datetime,utc=True)
py_result_csv['py_delta'] = ((py_result_csv['commit_date'] - py_result_csv['published_date']).dt.days).apply(lambda val: val if val>0 else 0)

# ADDED DROPPING OF 'Unnamed: 0' COLUMN - DON'T KNOW WHY IT'S THERE
py_stat_1 = py_result_csv.query('py_delta >= 0').drop(columns=['impact_score', 'Unnamed: 0']).groupby(py_result_csv['commit_date'].dt.year).agg('mean')

stat_1 = pd.concat([py_stat_1, js_stat_1], axis=1).query('js_delta > 0 or py_delta > 0')
stat_1_ax = stat_1.plot(kind='bar', title='Average number of days between mitigation commit date and CVE publish date grouped by years', figsize=(20,10))
stat_1_ax.set(xlabel="Year", ylabel="Days")

plt.show()