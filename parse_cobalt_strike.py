# pylint: disable = line-too-long, too-many-lines, no-name-in-module,
# pylint: disable = import-error, multiple-imports, pointless-string-statement,
# pylint: disable = wrong-import-order wrong-import-position invalid-name
# pylint: disable = redefined-outer-name

"""THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

# Active C2 IOCs
import os
from cymruwhois import Client
from tabulate import tabulate
from datetime import datetime
import time
cwd = os.getcwd()
c = Client()

now = datetime.now()
print("now =", now)
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
print("date and time =", dt_string)

uniq_ips = []
tabulate_data = []

for root, dirs, files in os.walk(cwd):
    for file in files:
        if file.endswith(".csv"):
            print("[+]info, found..." + str(os.path.join(root, file)))
            file = open(os.path.join(root, file), 'r')
            for eachline in file.readlines():
                ip_str = str(eachline.split()[0])
                if ip_str not in uniq_ips:
                    uniq_ips.append(ip_str)

print("[+]info, found ..." + str(len(uniq_ips)) + " IP's")
loop_counter = 0

for each in uniq_ips:
    try:
        print("[+]debug, " + str(each))
        tmp_data = []
        loop_counter += 1
        r = c.lookup(each)
        tmp_data.append(each)
        tmp_data.append(str(r.owner))
        print(r)
        tabulate_data.append(tmp_data)
        print("[+]info, " + str(loop_counter) + "/" + str(len(uniq_ips)))
    except BaseException as e:
        print(e)
        pass


sorted_c2_ioc_list = sorted(tabulate_data, key=lambda x: x[1])
print(
    tabulate(
        sorted_c2_ioc_list,
        headers=[
            "entry",
            "owner"],
        tablefmt="grid"))

file_string = "active_c2_ioc_public_" + \
    str(time.strftime("%Y%m%d-%H%M%S") + ".txt")
f = open(file_string, "w")
f.write(str(tabulate(
    sorted_c2_ioc_list,
    headers=[
        "ip_entry",
        "owner"],
    tablefmt="grid")))


f.write("\n\n\nLast Modified: " + str(dt_string) + "\n")
f.write("Last Modified: " + str(dt_string) + "\n")
f.write("Last Modified: " + str(dt_string) + "\n")
f.close()
