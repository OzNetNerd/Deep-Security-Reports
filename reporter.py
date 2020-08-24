import os
import csv
import time
import sys
import warnings
import argparse
import deepsecurity as api
from deepsecurity.rest import ApiException

if not sys.warnoptions:
    warnings.simplefilter('ignore')


class Ds:
    def __init__(self, dsm_address):

        try:
            ds_api_key = os.environ['DS_KEY']
            self.api_version = os.environ.get('DS_API_VERSION', 'v1')

        except KeyError:
            sys.exit('"DS_KEY" environment variables are not set. Please set them and try again.')

        config = api.Configuration()
        config.host = dsm_address
        config.api_key['api-secret-key'] = ds_api_key

        self.api_client = api.ApiClient(config)

    def get_app_types(self):
        try:
            app_type_api = api.ApplicationTypesApi(self.api_client)
            app_list = app_type_api.list_application_types(self.api_version)

        except ApiException as e:
            return 'Exception: ' + str(e)

        app_types = dict()

        for app in app_list.application_types:
            app_types[app.id] = app

        return app_types

    def get_computers(self):
        expand = api.Expand(api.Expand.intrusion_prevention)

        try:
            computers_api = api.ComputersApi(self.api_client)
            computer_list = computers_api.list_computers(self.api_version, expand=expand.list(), overrides=False)

        except ApiException as e:
            return 'Exception: ' + str(e)

        computers = dict()

        for computer in computer_list.computers:
            computers[computer.host_name] = computer

        return computers

    def get_ips_rules(self):
        ips_rules = dict()

        search_criteria = api.SearchCriteria()
        search_criteria.id_value = 0
        search_criteria.id_test = 'greater-than'

        search_filter = api.SearchFilter()
        search_filter.max_items = 5000
        search_filter.search_criteria = [search_criteria]

        ips_api = api.IntrusionPreventionRulesApi(self.api_client)

        while True:
            try:
                rule_list = ips_api.search_intrusion_prevention_rules(self.api_version, search_filter=search_filter)
                num_found = len(rule_list.intrusion_prevention_rules)

                if num_found == 0:
                    break

            except ApiException as e:
                return 'Exception: ' + str(e)

            for rule in rule_list.intrusion_prevention_rules:
                ips_rules[rule.id] = rule

            last_id = rule_list.intrusion_prevention_rules[-1].id
            search_criteria.id_value = last_id

        return ips_rules

    @staticmethod
    def epoch_to_timestamp(epoch_time):
        epoch_strip = str(epoch_time)[:-3]
        epoch = int(epoch_strip)

        return time.strftime('%d/%m/%Y, %H:%M:%S %Z', time.localtime(epoch))

    @staticmethod
    def generate_output(report_entries, filename):
        with open(filename, 'w') as f:
            writer = csv.writer(f)
            writer.writerows(report_entries)


class Ips(Ds):
    def __init__(self, ds_address, app_names=None):
        super().__init__(ds_address)

        self.app_names = app_names
        self.ips_rules = self.get_ips_rules()
        self.app_types = self.get_app_types()
        self.computers = self.get_computers()

    def _app_name_lookup(self, rule_info):
        for app_name in self.app_names:
            for info in rule_info:

                if not isinstance(info, str):
                    continue

                if app_name.lower() in info.lower():
                    rule_info.append(app_name)

                    return

        rule_info.append('N/A')

    def _split_cve_entries(self, rule_info, cves, base_copy):
        rules = []

        for cve in cves:
            new_rule = rule_info.copy()
            new_rule.insert(8, cve)

            cve_year = cve.split('-')[1]
            new_rule.insert(9, cve_year)

            new_base = base_copy.copy()
            new_base.extend(new_rule)

            rules.append(new_base)

        return rules

    def _add_report_entry(self, base_copy, rule_id, split_cves):
        rule = self.ips_rules[rule_id]

        app_id = rule.application_type_id
        app = self.app_types[app_id]

        if app.port_multiple:
            app_ports = ', '.join(app.port_multiple)

        else:
            app_ports = app.port_list_id

        rule_info = [
            rule.name,
            rule.id,
            rule.description,
            app.name,
            app.description,
            app_ports,
            app.direction,
            app.protocol,
            rule.cvss_score,
            rule.severity,
            rule.type,
        ]

        if self.app_names:
            self._app_name_lookup(rule_info)

        if isinstance(rule.cve, list):
            if split_cves:
                split_rules = self._split_cve_entries(rule_info, rule.cve, base_copy)

                return split_rules

            else:
                rule.cve = ', '.join(rule.cve)

        rule_info.insert(8, rule.cve)

        if split_cves:
            rule_info.insert(9, '')

        base_copy.extend(rule_info)

        return base_copy

    def gather_report_data(self, split_cves=False):
        report_data = [['Hostname', 'Display Name', 'Host Description', 'Platform', 'Last IP Used', 'Agent Version',
                        'Policy ID', 'Last Agent Comms.', 'IPS Agent State', 'IPS Status', 'Rule Name', 'Rule ID',
                        'Rule Description', 'App Category', 'App Description', 'App Port(s)', 'Direction',
                        'Protocol', 'CVE(s)', 'CVSS Score', 'Severity', 'Rule Type']]

        if split_cves:
            cve_year_index = report_data[0].index('CVE(s)') + 1
            report_data[0].insert(cve_year_index, 'CVE Year')

        if self.app_names:
            report_data[0].append('App Name')

        for hostname, data in self.computers.items():
            base_computer_details = [
                hostname,
                data.display_name,
                data.description,
                data.platform,
                data.last_ip_used,
                data.agent_version,
                str(data.policy_id),
                self.epoch_to_timestamp(data.last_agent_communication),
                data.intrusion_prevention.module_status.agent_status,
                data.intrusion_prevention.module_status.agent_status_message,
            ]

            # iterate through applied rules
            for rule_id in data.intrusion_prevention.rule_ids:
                base_copy = base_computer_details.copy()
                output = self._add_report_entry(base_copy, rule_id, split_cves)

                if isinstance(output[0], list):
                    report_data.extend(output)

                else:
                    report_data.append(output)

        return report_data

    def gather_summary_data(self):
        summary_data = [['Hostname', 'Platform', 'Last Agent Comms.', 'IPS Status', '# of IPS Rules']]

        computers = self.get_computers()

        for hostname, data in self.computers.items():
            status_msg = data.intrusion_prevention.module_status.agent_status_message
            applied_rules = status_msg.rsplit(', ', 1)[1]
            num_rules = applied_rules.split()[0]

            computer_details = [
                hostname,
                data.platform,
                self.epoch_to_timestamp(data.last_agent_communication),
                data.intrusion_prevention.module_status.agent_status,
                num_rules,
            ]

            summary_data.append(computer_details)

        return summary_data


def args_menu():
    formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=52)
    parser = argparse.ArgumentParser(description='Deep Security IPS Report', formatter_class=formatter)
    parser.add_argument("--report-filename", default='ips_report.csv', type=str, help='IPS report filename '
                                                                                      '(default: ips_report.csv')
    parser.add_argument("--summary-filename", default='ips_summary.csv', type=str, help='IPS summary filename '
                                                                                        '(default: ips_summary.csv')
    parser.add_argument("--app-names", default='', nargs='*', type=str,
                        help='App names to search for in the IPS report')
    parser.add_argument('--dsm-address', default='https://app.deepsecurity.trendmicro.com/api', type=str,
                        help='e.g https://app.deepsecurity.trendmicro.com/api (default)')

    args = parser.parse_args()
    args_dict = vars(args)

    return args_dict


def main():
    args = args_menu()

    dsm_address = args['dsm_address']
    app_names = args['app_names']
    report_filename = args['report_filename']
    summary_filename = args['summary_filename']

    ips = Ips(dsm_address, app_names)

    report_data = ips.gather_report_data(split_cves=True)
    ips.generate_output(report_data, report_filename)

    summary_data = ips.gather_summary_data()
    ips.generate_output(summary_data, summary_filename)

    print('Done')


if __name__ == '__main__':
    main()
