import csv
import sslyze
from threading import Thread
from queue import Queue


domains = []

with open(r"Data\OneMillionSites.csv", "r") as csv_file:
    csv_reader = csv.DictReader(csv_file)
    try:
        for row in csv_reader:
            if ".com" in row['Domain'] or ".org" in row['Domain']:
                domains.append(row['Domain'])
            else:
                pass
    except:
        pass

class SSLCheckWorker(Thread):
    def __init__(self, q):
        Thread.__init__(self)
        self.q = q
        self.domain = ''

    def process(self):
    # First validate that we can connect to the servers we want to scan
        servers_to_scan = []
        try:
            server_location = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(self.domain, 443)
        except:
            exit

        try:
            server_info = sslyze.ServerConnectivityTester().perform(server_location)
            servers_to_scan.append(server_info)
        except:
            exit

        scanner = sslyze.Scanner()

        # Then queue some scan commands for each server
        for server_info in servers_to_scan:
            server_scan_req = sslyze.ServerScanRequest(
                server_info=server_info, scan_commands={sslyze.ScanCommand.CERTIFICATE_INFO, sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES, sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES},
            )
            scanner.queue_scan(server_scan_req)

        # Then retrieve the result of the scan commands for each server
        for server_scan_result in scanner.get_results():
            print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

            # Scan commands that were run with no errors       
            try:
                tls12_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES]
                print("\nTLS 1.2 Ciphers")
                for accepted_cipher_suite in tls12_result.accepted_cipher_suites:
                    print(accepted_cipher_suite.cipher_suite.name)
            except KeyError:
                pass

            try:
                tls11_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES]
                print("\nTLS 1.1 Ciphers")
                for accepted_cipher_suite in tls11_result.accepted_cipher_suites:
                    print(accepted_cipher_suite.cipher_suite.name)
            except KeyError:
                pass

    def run(self):
        while True:
            # Get the work from the queue and expand the tuple
            self.domain = self.q.get()
            print(f"Running for {self.domain}")
            self.process()
            self.q.task_done()

r = len(domains)

def main():
    q = Queue()
    
    for x in range(1000):
        worker = SSLCheckWorker(q)
        worker.daemon = True
        worker.start()
    
    for domain in domains[:10]:
        q.put(domain)
    
    print("Queueing Complete")
    q.join()

if __name__ == '__main__':
    main()