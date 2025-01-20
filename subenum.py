banner = """
 _______ _     _ ______  _______ __   _ _     _ _______
 |______ |     | |_____] |______ | \  | |     | |  |  |
 ______| |_____| |_____] |______ |  \_| |_____| |  |  |
                                   by zen
"""

try:
    from requests import Session
    from requests.auth import HTTPBasicAuth
    from bs4 import BeautifulSoup
    from fake_useragent import UserAgent
    from urllib.parse import unquote
    from argparse import ArgumentParser
    from os import getenv, getcwd, mkdir
    from os.path import join, exists
    from dotenv import load_dotenv
    from threading import Thread
    from time import time, sleep
    from json import load, dump
except KeyboardInterrupt:
    print(banner)
    print("[*] Exiting...")


# main CLI function
def main():

    # print the banner
    print(banner)

    # parse the cli parameters
    parser = ArgumentParser(description="Subdomains Enumerator")
    parser.add_argument('domain', type=str, help="Domain to search for subdomains")
    parser.add_argument('-o', '--output', type=str, help="Save the output in a text file")
    parser.add_argument('-f', '--fast', action='store_true', help="Enable fast mode")
    parser.add_argument('-c', '--cache', type=str, help="Cache all query to a folder")
    parser.add_argument('-q', '--quiet', action='store_true', help="Disable verbosity")
    args = parser.parse_args()

    # load the api keys
    load_dotenv(join(getcwd(), '.env'))
    load_dotenv()
    vt_api_key = getenv('VIRUSTOTAL_API_KEY')
    shodan_api_key = getenv('SHODAN_API_KEY')
    censys_appid = getenv('CENSYS_APP_ID')
    censys_secret = getenv('CENSYS_SECRET')

    # get the subdomains from subenum
    verbose = True if args.quiet == False else False
    subenum = SubEnum(
        verbose=verbose,
        vt_api_key=vt_api_key,
        shodan_api_key=shodan_api_key,
        censys_appid=censys_appid,
        censys_secret=censys_secret,
        fast=args.fast,
        cache=args.cache
    )
    subdomains = subenum.get_subdomains(args.domain)

    # print the subdomains is there is no output
    if args.output is None:
        print("")
        for subdomain in subdomains:
            print(subdomain)
    
    # dump the subdomains list to the output file
    else:
        with open(args.output, 'w') as output_file:
            for subdomain in subdomains:
                output_file.write(subdomain + '\n')


# SubEnum controller
class SubEnum():

    # create a subenum object
    def __init__(self, verbose=True, vt_api_key=None, shodan_api_key=None, censys_appid=None, censys_secret=None, fast=False, cache=None):
        self.verbose = verbose

        # load all the modules
        self.modules = []
        self.modules.append(ThreatCrowd(verbose=verbose, cache=cache))
        self.modules.append(CertificatesSearch(verbose=verbose, cache=cache))
        #self.modules.append(DNSDumpster(verbose=verbose, cache=cache))
        self.modules.append(MerkleMap(verbose=verbose, cache=cache))
        self.modules.append(Google(verbose=verbose, fast=fast, cache=cache))
        self.modules.append(Bing(verbose=verbose, fast=fast, cache=cache))
        self.modules.append(Yahoo(verbose=verbose, fast=fast, cache=cache))

        # load all the modules that needs api keys
        if vt_api_key is not None:
            self.modules.append(VirusTotal(vt_api_key, verbose=verbose, fast=fast, cache=cache))
            print(f"[*] \033[92mVirusTotal\033[0m api key loaded!.")
        if shodan_api_key is not None:
            self.modules.append(Shodan(shodan_api_key, verbose=verbose, cache=cache))
            print(f"[*] \033[92mShodan\033[0m api key loaded!.")
        if censys_appid is not None and censys_secret is not None:
            self.modules.append(Censys(censys_appid, censys_secret, verbose=verbose, fast=fast, cache=cache))
            print(f"[*] \033[92mCensys\033[0m api key loaded!.")

    # get a list of subdomains
    def get_subdomains(self, domain):

        # get the subdomains from all the modules
        start_time = time()
        status, subdomains = self.run_modules_scan(domain)
        elapsed_time = "%0.2f" % (time() - start_time)

        # sort all the subdomains
        subdomains = self.sort_subdomains(subdomains)

        # print the number of subdomains found
        if self.verbose == True:
            print(f"[*] Found a total of {len(subdomains)} subdomains in {elapsed_time} secs.")

        # return all the subdomains
        return subdomains
    
    # run all the modules to scan for subdomains
    def run_modules_scan(self, domain):

        # create a list of all the subdomains found
        subdomains = []

        # start a thread for each modules
        threads = []
        for module in self.modules:
            thread = Thread(target=module.get_subdomains, args=(domain,))
            threads.append(thread)
            thread.start()

        # wait for all the threads to finish
        for thread in threads:
            thread.join()

        # merge all the subdomains list
        subdomains = []
        for module in self.modules:
            if module.subdomains is not None:
                for subdomain in module.subdomains:
                    if subdomain not in subdomains:
                        subdomains.append(subdomain)

        # build a list of status
        status_list = {}
        for module in self.modules:
            status_list[module.base_name] = module.status

        # return the status and subdomains found
        return status_list, subdomains

    # sort a list of subdomains
    def sort_subdomains(self, subdomains):
        valid_subdomains = []
        for subdomain in subdomains:
            if all((char.isalnum() or char in ['-', '.']) for char in subdomain) == True:
                valid_subdomains.append(subdomain)
                continue
        return sorted(valid_subdomains)


# default module api class
class ModuleApi:

    # create an api object
    def __init__(self, verbose=True, fast=False, cache=None):
        self.base_name = self.__class__.__name__
        self.session = Session()
        self.verbose = verbose
        self.subdomains = None
        self.fast_scan = fast
        self.status = 'Waiting'
        self.cache = cache

    # get the subdomains from the api
    def get_subdomains(self, domain):

        # update the status
        self.status = 'Scanning'
        self.print("Starting subdomains discovery...")

        # load the cache if possible
        if self.in_cache(domain) == True:
            self.subdomains = self.load_cache(domain)
            subdomains_count = len(self.subdomains)
            self.status = 'Cached'
            self.print(f"{subdomains_count if subdomains_count > 0 else 'no'} subdomain{'s' if subdomains_count != 1 else ''} found.")
            return self.subdomains

        # query the subdomains
        response = self.query_domain(domain)
        if response is None:
            return None

        # parse the subdomains from the response
        self.subdomains = self.parse_query_response(response, domain)
        if self.subdomains is None:
            return None

        # save the cache if needed
        if self.cache is not None:
            self.save_cache(domain, self.subdomains)

        # update the status
        if self.status == 'Scanning':
            self.status = 'Scanned'
        
        # return the subdomains
        subdomains_count = len(self.subdomains)
        self.print(f"{subdomains_count if subdomains_count > 0 else 'no'} subdomain{'s' if subdomains_count != 1 else ''} found.")
        return self.subdomains
    
    # query the domain
    def query_domain(self, domain):
        self.status = 'query_domain not implemented'
        return None
    
    # parse the query response
    def parse_query_response(self, text, domain):
        self.status = 'parse_query_response not implemented'
        return None
    
    # get a domain from an url
    def get_domain_from_url(self, url):

        # remove the protocol
        if url.startswith('http://') == True:
            url = url[7:]
        elif url.startswith('https://') == True:
            url = url[8:]
        else:
            return None
        
        # remove the path
        pos = url.find('/')
        if pos != -1:
            url = url[:pos]

        # remove the parameters
        pos = url.find('?')
        if pos != -1:
            url = url[:pos]

        # remove the port
        pos = url.find(':')
        if pos != -1:
            url = url[:pos]

        # return the url domain
        return url
    
    # get a domain from a wildcard domain
    def get_domain_from_wildcard(self, domain):

        # remove the wildcards
        pos = domain.find('*.')
        while pos != -1:
            domain = domain[pos + 2:]
            pos = domain.find('*.')

        # browse each wildcards
        pos = domain.find('*')
        while pos != -1:

            # remove the leading wildcards
            if pos == 0:
                domain = domain[1:]

            # remove the wildcard left from the domain
            else:

                # do not take domain ending with a wildcard
                if pos + 1 > len(domain):
                    return None

                # remove the wildcard from the subdomain
                cleaned_domain = domain[:pos] + domain[pos + 1:]
                domain = cleaned_domain
                
            # check the next wildcard
            pos = domain.find('*')

        # return the domain
        return domain
    
    # print a message from the module
    def print(self, text):
        if self.verbose != False:
            print(f"[*] \033[92m{self.base_name}\033[0m: {text}")

    # print an error message from the module
    def print_error(self, text):
        if self.verbose != False:
            self.print(f"\033[91merror\033[0m: {text}")

    # init the cache
    def init_cache(self):
        if self.cache is not None:
            try:
                mkdir(self.cache)
            except FileExistsError:
                pass
            try:
                mkdir(join(self.cache, self.base_name))
            except FileExistsError:
                pass

    # check if a query is in cache
    def in_cache(self, query, page=None):
        if self.cache is None:
            return False
        query = self.sanatize_cache_query(query)
        file_name = f"{query}.json" if page is None else f"{query}.{page}.json"
        file_path = join(self.base_name, file_name)
        return exists(join(self.cache, file_path))
    
    # load a query from the cache
    def load_cache(self, query, page=None):
        if self.cache is None:
            return None
        query = self.sanatize_cache_query(query)
        file_name = f"{query}.json" if page is None else f"{query}.{page}.json"
        file_path = join(self.base_name, file_name)
        with open(join(self.cache, file_path), 'r') as json_file:
            subdomains = load(json_file)
        return subdomains
    
    # load a cursor from the cache
    def load_cache_cursor(self, query, page=None):
        if self.cache is None:
            return None
        query = self.sanatize_cache_query(query)
        file_name = f"{query}.cursor.json" if page is None else f"{query}.{page}.cursor.json"
        file_path = join(self.base_name, file_name)
        with open(join(self.cache, file_path), 'r') as json_file:
            subdomains = load(json_file)
        return subdomains
    
    # save a query results to the cache
    def save_cache(self, query, subdomains, page=None):
        if self.cache is not None:
            self.init_cache()
            query = self.sanatize_cache_query(query)
            file_name = f"{query}.json" if page is None else f"{query}.{page}.json"
            file_path = join(self.base_name, file_name)
            with open(join(self.cache, file_path), 'w') as json_file:
                dump(subdomains, json_file, indent=4)
    
    # save a cursor results to the cache
    def save_cache_cursor(self, query, cursor, page=None):
        if self.cache is not None:
            self.init_cache()
            query = self.sanatize_cache_query(query)
            file_name = f"{query}.cursor.json" if page is None else f"{query}.{page}.cursor.json"
            file_path = join(self.base_name, file_name)
            with open(join(self.cache, file_path), 'w') as json_file:
                dump(cursor, json_file, indent=4)

    # sanatize cache queries
    def sanatize_cache_query(self, query):
        return query
    

# default module search engine class
class ModuleSearchEngine(ModuleApi):

    # get the subdomains from the search engine
    def get_subdomains(self, domain):

        # update the status
        self.status = 'Scanning'
        self.print("Starting subdomains discovery...")

        # query the first 10 pages
        self.subdomains = []
        for page in range(1, 10):

            # load the cache if possible
            if self.in_cache(domain, page=page) == True:
                page_subdomains = self.load_cache(domain, page=page)

            # query the current page
            else:
                response = self.query_domain_page(domain, page)
                if response is None:
                    break

                # parse the subdomains from the page response
                page_subdomains = self.parse_query_response(response, domain)
                if page_subdomains is None:
                    break

                # save the cache if needed
                if self.cache is not None:
                    self.save_cache(domain, page_subdomains, page=page)

            # add the subdomains found to the list
            for subdomain in page_subdomains:
                if subdomain not in self.subdomains:
                    self.subdomains.append(subdomain)

            # stop at the first page if we are in fast mode
            if self.fast_scan == True:
                break

        # update the status
        if self.status == 'Scanning':
            self.status = 'Scanned'

        # return the complete list of all subdomains found
        subdomains_count = len(self.subdomains)
        self.print(f"{subdomains_count if subdomains_count > 0 else 'no'} subdomain{'s' if subdomains_count != 1 else ''} found.")
        return self.subdomains
    
    # query a domain page
    def query_domain_page(self, domain, page):
        self.status = 'query_domain_page not implemented'
        return None
    

# default module api class with a key
class ModuleApiWithKey(ModuleApi):

    # create an api object
    def __init__(self, api_key, verbose=True, fast=False, cache=None):
        super().__init__(verbose=verbose, fast=fast, cache=cache)
        self.api_key = api_key


# default module api class with an auth
class ModuleApiWithAuth(ModuleApi):

    # create an api object
    def __init__(self, username, password, verbose=True, fast=False, cache=None):
        super().__init__(verbose=verbose, fast=fast, cache=cache)
        self.auth = HTTPBasicAuth(username, password)


# ThreatCrowd api
class ThreatCrowd(ModuleApi):

    # create a ThreatCrowd object
    def __init__(self, verbose=True, cache=None):
        super().__init__(verbose=verbose, cache=cache)
        self.base_url = "http://ci-www.threatcrowd.org/graphHtml.php"

    # download a domain report
    def query_domain(self, domain):

        # query the website
        params = { 'domain': domain }
        response = self.session.get(self.base_url, params=params)

        # check for errors
        if response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the text response
        return response.text
    
    # parse a domain report
    def parse_query_response(self, text, domain):

        # find where the subdomains are
        pos = text.find("elements: {")
        end_pos = text.find("edges: [")
        text = text[pos:end_pos]
        lines = text.split('\n')

        # parse all subdomains
        subdomains = []
        for line in lines:
            pos = line.find("id: '")
            if pos != -1:
                id = line[pos + 5:]
                end_pos = id.find("'")
                id = id[:end_pos]
                if id.endswith(domain) == True:
                    while id[0] == '.':
                        id = id[1:]
                    if id == domain:
                        continue
                    if id in subdomains:
                        continue
                    subdomains.append(id)

        # return the list of subdomains
        return subdomains


# crt.sh api
class CertificatesSearch(ModuleApi):

    # create a crtsh object
    def __init__(self, verbose=True, cache=None):
        super().__init__(verbose=verbose, cache=cache)
        self.base_url = "https://crt.sh/"
    
    # query a domain informations from crt.sh
    def query_domain(self, domain, try_count=0):

        # query the website
        params = { 'q': domain }
        response = self.session.get(self.base_url, params=params)

        # check for errors
        if response.status_code in [502, 503]:
            if try_count < 3:
                return self.query_domain(domain, try_count=try_count + 1)
            error_text = f"service is currently unavailable."
            self.print_error(error_text)
            self.status = error_text
            return None
        elif response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the text response
        return response.text
    
    # parse a query response from crt.sh
    def parse_query_response(self, text, domain):

        # convert the text response to html
        soup = BeautifulSoup(text, features="html.parser")

        # parse the subdomains from the html
        subdomains = []
        outers = soup.find_all('td', {'class': 'outer'})
        for outer in outers:
            elems_list = outer.find_all("tr")
            for elem in elems_list:
                fields_list = elem.find_all('td')
                if len(fields_list) == 7:
                    field_id = 0
                    for field in fields_list:
                        if field_id in [4, 5]:
                            lines = str(field).split('<br/>')
                            for subdomain in lines:
                                if subdomain.startswith('<td>') == True:
                                    subdomain = subdomain[4:]
                                if subdomain.endswith('</td>') == True:
                                    subdomain = subdomain[:-5]
                                if subdomain.endswith(domain) == False:
                                    continue
                                if subdomain not in subdomains:
                                    subdomains.append(subdomain)
                        field_id += 1
        
        # return the subdomains found
        return subdomains


# Google api
class Google(ModuleSearchEngine):

    # create a google object
    def __init__(self, verbose=True, fast=False, cache=None):
        super().__init__(verbose=verbose, fast=fast, cache=cache)
        self.base_url = "https://www.google.com/search"

    # query a domain page from google
    def query_domain_page(self, domain, page):

        # query the website
        headers = { 'user-agent': UserAgent().random }
        params = { 'q': domain, 'start': (page - 1) * 10 }
        response = self.session.get(self.base_url, headers=headers, params=params)

        # check for errors
        if response.status_code == 429:
            error_text = "too many requests."
            self.print_error(error_text)
            self.status = error_text
            return None
        elif response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the response text
        return response.text
    
    # parse the query response from google
    def parse_query_response(self, text, domain):

        # convert the text response to html
        soup = BeautifulSoup(text, features="html.parser")
        if soup.find('title').text.find(domain) == -1:
            error_text = "captcha detected."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # find the links from the html
        rso = soup.find('div', {'id': 'rso'})
        urls = []
        total_urls = 0
        if rso is not None:
            for tag in rso:
                a_tags = tag.find_all('a')
                for a_tag in a_tags:
                    total_urls += 1
                    try:
                        if a_tag['href'] not in urls:
                            urls.append(a_tag['href'])
                    except KeyError:
                        pass
        
        # check if we are shadow banned
        if total_urls == 0:
            error_text = "shadow ban detected."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # parse a subdomains list from the urls list
        subdomains = []
        for url in urls:
            subdomain = self.get_domain_from_url(url)
            if subdomain is not None and subdomain.endswith(domain) == True:
                if subdomain not in subdomains:
                    subdomains.append(subdomain)

        # return the subdomains list
        return subdomains


# Bing api
class Bing(ModuleSearchEngine):

    # create a bing object
    def __init__(self, verbose=True, fast=False, cache=None):
        super().__init__(verbose=verbose, fast=fast, cache=cache)
        self.base_url = "https://www.bing.com/search"
        self.user_agent = UserAgent().random

    # query the domain from bing
    def query_domain_page(self, domain, page):
        
        # query the website
        headers = { 'user-agent': self.user_agent }
        first = '1' if page == 1 else f"{(page - 1)}1"
        params = { 'q': domain, 'first': first }
        response = self.session.get(self.base_url, headers=headers, params=params)

        # check for errors
        if response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the response text
        return response.text
    
    # parse a query response from bing
    def parse_query_response(self, text, domain):

        # convert the text response to html
        try:
            soup = BeautifulSoup(text, features="html.parser")
        except TypeError:
            error_text = "received unknown content type."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # check if we got a captcha
        title = soup.find('title').text
        if title.find(domain) == -1:
            error_text = "captcha detected."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # parse the results from the html
        b_results = soup.find('ol', {'id': 'b_results'})
        results = b_results.find_all('li', {'class': 'b_algo'})

        # parse all subdomains from the results
        subdomains = []
        results_domains = []
        for result in results:
            link = result.find('a', {'class': 'tilk'})
            if link is None:
                self.print_error("shadow ban detected.")
                return None
            link = link['href']
            if link.startswith('https://') == True:
                result_domain = link[8:]
            elif link.startswith('http://') == True:
                result_domain = link[7:]
            pos = result_domain.find('/')
            if pos != -1:
                result_domain = result_domain[:pos]
            if result_domain not in results_domains:
                results_domains.append(result_domain)
            if result_domain.endswith(domain) == True:
                subdomains.append(result_domain)
        
        # check if we got a shadow ban
        if results_domains == [ 'www.bing.com' ]:
            error_text = "shadow ban detected."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the list of subdomains
        return subdomains


# Yahoo api
class Yahoo(ModuleSearchEngine):

    # create a yahoo object
    def __init__(self, verbose=True, fast=False, cache=None):
        super().__init__(verbose=verbose, fast=fast, cache=cache)
        self.base_url = "https://fr.search.yahoo.com/search"
        self.user_agent = UserAgent().random

    # query the domain from yahoo
    def query_domain_page(self, domain, page):
        
        # query the website
        headers = { 'user-agent': self.user_agent }
        params = {
            'p': domain,
            'ei': 'UTF-8',
            'nocache': 1,
            'nojs': 1
        }
        if page > 1:
            page_offset = ((page - 1) * 7) + 1
            params['b']  = page_offset
        response = self.session.get(self.base_url, headers=headers, params=params)

        # check for errors
        if response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the response
        return response
    
    # parse a query response from yahoo
    def parse_query_response(self, response, domain):

        # parse the html text
        text = response.text
        try:
            soup = BeautifulSoup(text, features="html.parser")
        except TypeError:
            error_text = "received unknown content type."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # find all links
        links = soup.find_all('a')
        subdomains = []
        for link in links:

            # parse the link url
            try:
                url = link['href']
            except KeyError:
                continue

            # check if the url is 'yahoo encoded'
            if url.startswith("https://r.search.yahoo.com") == True:
                tokens = url.split('/')[3:]
                for token in tokens:
                    keyval = token.split('=')
                    if keyval[0] == 'RU':
                        url = unquote(keyval[1])
                        break

            # get the subdomain from the url
            subdomain = self.get_domain_from_url(url)
            if subdomain is not None and subdomain.endswith(domain) == True:
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
        
        # return the list of subdomains found
        return subdomains


# VirusTotal api
class VirusTotal(ModuleApiWithKey):

    # create a VirusTotal object
    def __init__(self, api_key, verbose=True, fast=False, cache=None):
        super().__init__(api_key, verbose=verbose, fast=fast, cache=cache)
        self.base_url = "https://www.virustotal.com/api/v3/domains/"

    # get a list of subdomains
    def get_subdomains(self, domain):

        # update the status
        self.status = 'Scanning'

        # download all subdomains from a domain
        self.print("Starting subdomains discovery...")
        self.subdomains = self.download_relationship(domain)

        # check if we got an error
        if self.subdomains is None:
            return None

        # update the status
        if self.status == 'Scanning':
            self.status = 'Scanned'
        
        # return the list of subdomains found
        subdomains_count = len(self.subdomains)
        self.print(f"{subdomains_count if subdomains_count > 0 else 'no'} subdomain{'s' if subdomains_count != 1 else ''} found.")
        return self.subdomains

    # download a relationship
    def download_relationship(self, domain):

        # load the cache if possible
        if self.in_cache(domain) == True:
            subdomains = self.load_cache(domain)
            cursor = self.load_cache_cursor(domain)

        # download the first domain page
        else:
            results = self.download_relationship_page(domain)
            if results is None:
                return None
            
            # parse the subdomains from the first page
            subdomains = []
            for subdomain in results['data']:
                if subdomain['id'] not in subdomains:
                    subdomains.append(subdomain['id'])

            # parse the next page cursor from the first page
            cursor = None
            if 'cursor' in results['meta']:
                cursor = results['meta']['cursor']

            # save the cache if needed
            if self.cache is not None:
                self.save_cache(domain, subdomains)
                self.save_cache_cursor(domain, cursor)

        # return the first page if we do a fast scan
        if self.fast_scan == True:
            return subdomains

        # download pages until there is no next one
        while cursor is not None:

            # load the cache if possible
            if self.in_cache(domain, page=cursor) == True:
                page_subdomains = self.load_cache(domain, page=cursor)
                cursor = self.load_cache_cursor(domain, page=cursor)

            # download the next domain page
            else:
                results = self.download_relationship_page(domain, cursor=cursor)
                if results is None:
                    break
                
                # parse the subdomains from the page
                page_subdomains = []
                for subdomain in results['data']:
                    if subdomain['id'] not in page_subdomains:
                        page_subdomains.append(subdomain['id'])

                # parse the next page cursor from the page
                next_cursor = None
                if 'cursor' in results['meta']:
                    next_cursor = results['meta']['cursor']

                # save the cache if needed
                if self.cache is not None:
                    self.save_cache(domain, page_subdomains, page=cursor)
                    self.save_cache_cursor(domain, next_cursor, page=cursor)
                cursor = next_cursor

            # add the subdomains from the page
            for subdomain in page_subdomains:
                if subdomain not in subdomains:
                    subdomains.append(subdomain)

        # return a list of all subdomains found
        return subdomains
    
    # download a relationship page
    def download_relationship_page(self, domain, cursor=None, limit=40):
        
        # query the api
        url = self.base_url + f"{domain}/subdomains"
        params = { 'limit': limit }
        if cursor is not None:
            params['cursor'] = cursor
        headers = { 'x-apikey': self.api_key }
        response = self.session.get(url, headers=headers, params=params)

        # check for errors
        if response.status_code == 401:
            if response.text.find("Wrong API key") != -1:
                error_text = f"invalid api key."
                self.print_error(error_text)
                self.status = error_text
            else:
                error_text = f"unauthorized."
                self.print_error(error_text)
                self.status = error_text
            return None
        elif response.status_code == 429:
            error_text = "too many requests."
            self.print_error(error_text)
            self.status = error_text
            return None
        elif response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the json response
        return response.json()


# Shodan api
class Shodan(ModuleApiWithKey):

    # create a shodan object
    def __init__(self, api_key, verbose=True, cache=None):
        super().__init__(api_key, verbose=verbose, cache=cache)
        self.base_url = "https://api.shodan.io/dns/domain/"
    
    # query a domain information from shodan
    def query_domain(self, domain):

        # query the api
        params = { 'key': self.api_key }
        response = self.session.get(self.base_url + domain, params=params)

        # check for errors
        if response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        
        # return the json response
        return response.json()
    
    # parse the query response
    def parse_query_response(self, data, domain):
        subdomains = []
        for subdomain in data["subdomains"]:
            full_subdomain = subdomain + '.' + domain
            if full_subdomain not in subdomains:
                subdomains.append(full_subdomain)
        return subdomains


# Censys api
class Censys(ModuleApiWithAuth):

    # create a censys object
    def __init__(self, app_id, secret, verbose=True, fast=False, cache=None):
        super().__init__(app_id, secret, verbose=verbose, fast=fast, cache=cache)
        self.base_url = 'https://search.censys.io/api/v2/certificates/search'

    # get the subdomains from a domain
    def get_subdomains(self, domain):

        # update the status
        self.status = 'Scanning'
        self.print("Starting subdomains discovery...")
        self.subdomains = []

        # load the cache if possible
        if self.in_cache(domain) == True:
            page_subdomains = self.load_cache(domain)
            cursor = self.load_cache_cursor(domain)

        # get the first page
        else:
            response = self.query_domain_page(domain)
            if response is None:
                return self.subdomains
            
            # parse the subdomains from the first pages
            page_count = 1
            page_subdomains = self.parse_query_response(response, domain)

            # get the next page cursor if any
            cursor = response['result']['links']['next']

            # save the cache if needed
            if self.cache is not None:
                self.save_cache(domain, page_subdomains)
                self.save_cache_cursor(domain, cursor)
        
        # add the subdomains to the list
        for subdomain in page_subdomains:
            if subdomain in self.subdomains:
                continue
            self.subdomains.append(subdomain)

        # check if we are in fast mode
        if self.fast_scan == True:
            if self.status == 'Scanning':
                self.status = 'Scanned'
            return self.subdomains

        # get all next pages
        while cursor != '' and page_count < 10:
            page_count += 1

            # load the cache if possible
            if self.in_cache(domain, page=cursor) == True:
                page_subdomains = self.load_cache(domain, page=cursor)
                cursor = self.load_cache_cursor(domain, page=cursor)

            # get the next subdomains
            else:
                sleep(0.4)
                response = self.query_domain_page(domain, cursor=cursor)
                if response is None:
                    break
                page_subdomains = self.parse_query_response(response, domain)
            
                # get the next page cursor if any
                next_cursor = response['result']['links']['next']

                # save the cache if needed
                if self.cache is not None:
                    self.save_cache(domain, page_subdomains, page=cursor)
                    self.save_cache_cursor(domain, next_cursor, page=cursor)
                cursor = next_cursor
            
            # add the subdomains to the list
            for subdomain in page_subdomains:
                if subdomain in self.subdomains:
                    continue
                self.subdomains.append(subdomain)

        # update the status
        if self.status == 'Scanning':
            self.status = 'Scanned'
    
        # return the list of subdomains found
        subdomains_count = len(self.subdomains)
        self.print(f"{subdomains_count if subdomains_count > 0 else 'no'} subdomain{'s' if subdomains_count != 1 else ''} found.")
        return self.subdomains

    # get a domain page
    def query_domain_page(self, domain, cursor=None):

        # query the api
        headers = { "Content-Type": "application/json" }
        params = {
            "q": domain,
            "per_page": 100,
            "cursor": cursor,
        }
        if cursor is not None:
            params['cursor'] = cursor

        # send the request
        response = self.session.get(self.base_url, headers=headers, params=params, auth=self.auth)
        
        # check for errors
        if response.status_code == 429:
            error_text = "too many requests."
            self.print_error(error_text)
            self.status = error_text
            return None
        elif response.status_code == 403:
            error_text = f"forbidden: '{response.json()['error']}'."
            self.print_error(error_text)
            self.status = error_text
            return None
        elif response.status_code != 200:
            error_text = f"received unknown response code: '{response.status_code}'."
            self.print_error(error_text)
            self.status = error_text
            return None

        # return the json response
        return response.json()
    
    # parse the subdomains from a query response
    def parse_query_response(self, response, domain):

        # check each certificate from the response
        subdomains = []
        hits = response['result']['hits']
        for certificate in hits:

            # check the common name
            subject_dn = certificate['parsed']['subject_dn']
            infos = subject_dn.split(", ")
            for info in infos:
                if info.startswith("CN=") == True:
                    common_name = info

            # check if this is a subdomain from our main domain
            subdomain = common_name[3:]
            if subdomain.endswith(domain) == True:

                # remove the wildcards from subdomain
                if subdomain.find('*') != -1:
                    subdomain = self.get_domain_from_wildcard(subdomain)
                    if subdomain is None:
                        continue
                
                # add the subdomain to the list
                if subdomain not in subdomains:
                    subdomains.append(subdomain)

            # check the alternate names
            alternate_names = certificate['names']
            for subdomain in alternate_names:

                # check if this is a subdomain from our main domain
                if subdomain.endswith(domain) != True:
                    continue

                # remove the wildcards from subdomain
                if subdomain.find('*') != -1:
                    subdomain = self.get_domain_from_wildcard(subdomain)
                    if subdomain is None:
                        continue

                # add the subdomain to the list
                if subdomain in subdomains:
                    continue
                subdomains.append(subdomain)

        # return the list of subdomains found
        return subdomains
    

# run the main function if needed
if __name__ == "__main__":
    main()
