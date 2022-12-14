import csv
import datetime
import collections
import statistics 

JS_CSV = "result_js.csv"
PY_CSV = "result_py.csv"
js_reader = csv.reader(open(JS_CSV, 'r'), delimiter=',', quotechar='"')
py_reader = csv.reader(open(PY_CSV, 'r'), delimiter=',', quotechar='"')



next(js_reader)
next(py_reader)
for r in js_reader, py_reader:
    print(r)
    y_dict = collections.defaultdict(list)
    for row in r:
        if row[5]:
            cwe = row[4]
            # print('-'.join([str(substring) for substring in row[2].split('-')[:-1]]))
            # print(row[5])
            # commit_date = datetime.datetime.strptime(row[2].split('+')[0], '%Y-%m-%d %H:%M:%S')
            commit_date = datetime.datetime.strptime('-'.join([str(substring) for substring in row[2].split('-')[:-1]]), '%Y-%m-%d %H:%M:%S')
            publish_date = datetime.datetime.strptime(row[5], '%Y-%m-%dT%H:%MZ')
            delta = (commit_date-publish_date).days if (commit_date-publish_date).days>0 else 0
            y_dict[commit_date.year].append(delta)
    for y in y_dict.keys():
        print(f"{y},{statistics.mean(y_dict[y])}")