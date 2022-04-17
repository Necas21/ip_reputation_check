from cProfile import label
import requests
import argparse
import sys
import matplotlib.pyplot as plt

# API Key can be created here: https://www.abuseipdb.com/
API_KEY = '<INSERT API KEY>'

# Loops through a file containing a list of IP addresses and returns a list
def get_ip_list(filename):

    ip_list = []
    try:
        file = open(filename, 'r')
    except:
        print(f'[-] File "{filename}" does not exist!')

    for line in file:
        ip_list.append(line.rstrip())

    return ip_list


# Queries the AbuseIPDB API for an IPs reputation and country
def get_ip_reputation(ip):

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    try:
        r = requests.get(url=url, headers=headers, params=querystring)
        decoded_response = r.json()
        reputation_score = decoded_response['data']['abuseConfidenceScore']
        country_code = decoded_response['data']['countryCode']
        return country_code, reputation_score
    except:
        print(f'[-] API request for "{ip}" failed!')


# Loops through a list of IP addresses and returns a dictionary containing the number of occurences of each IP
def build_ip_count(ip_list):
    ip_count = {}
    for ip in ip_list:
        if ip not in ip_count.keys():
            ip_count[ip] = 1
        else:
            ip_count[ip] = ip_count[ip] + 1

    return ip_count


# Draws a bar chart of the number of occurences of each IP
def draw_ip_count(ip_count):
    labels = []
    count = []

    for k in ip_count.keys():
        labels.append(k)
        count.append(ip_count[k])

    fig, ax = plt.subplots()
    width = 0.35
    ax.bar(labels, count, width)
    ax.set_ylabel('Count')
    ax.set_xlabel('IP Address')
    ax.set_title('Number of Connections per IP Address')
    plt.xticks(rotation=90)
    plt.show(block=False)
    

# Creates a dictionary containing the number of 'High' and 'Low' reputation IP addresses and then draws a stacked bar chart
def draw_stack_chart(ip_count):
    country_dict = {}
    for ip in ip_count.keys():
        country_code, reputation_score = get_ip_reputation(ip)
        if country_code not in country_dict.keys():
            severity_dict = {'High' : 0,
                             'Low' : 0}
            country_dict[country_code] = severity_dict
        if reputation_score > 25:
            country_dict[country_code]['High'] += ip_count[ip]
        else:
            country_dict[country_code]['Low'] += ip_count[ip]

    labels = []
    high_sev = []
    low_sev = []

    for country in country_dict.keys():
        labels.append(country)
        high_sev.append(country_dict[country]['High'])
        low_sev.append(country_dict[country]['Low'])

    fig, ax = plt.subplots()
    width = 0.35
    ax.bar(labels, low_sev, width, label='Low')
    ax.bar(labels, high_sev, width, label='High')
    ax.set_ylabel('Count')
    ax.set_xlabel('Country')
    ax.set_title('High/Low Severity Connections by Country')
    ax.legend()
    plt.show()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", dest="file", help="Specify a file containing a list of IP addresses.")

    if len(sys.argv) != 3:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    file = args.file
    ip_list = get_ip_list(file)
    ip_count = build_ip_count(ip_list)
    draw_ip_count(ip_count)
    draw_stack_chart(ip_count)


if __name__ == "__main__":
    main()
