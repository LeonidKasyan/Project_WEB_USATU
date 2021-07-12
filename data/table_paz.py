from prettytable import PrettyTable
import os

def table_paz():

    a = open("table/bd_paz.csv",'r')

    a = a.read().split('\n')
    l =[]
   #l1 = a[0]
    l1 = a[0].split(';')

    t = PrettyTable([l1[0],l1[1],l1[2],l1[3]])

    for i in range(1,len(a)-1):
        l = a[i].split(';')
        if(len(l) == 4):
            t.add_row(a[i].split(';'))

    code = t.get_html_string()

    if(os.path.exists('table/Table_paz.html')):
        os.remove('table\Table_paz.html')

    html_file = open('table/Table_paz.html','w')
    html_file = html_file.write(code)