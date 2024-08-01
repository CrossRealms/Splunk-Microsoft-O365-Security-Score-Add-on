import import_declare_test

import sys
import json

from splunklib import modularinput as smi

import input_module_graph_security_score_input as input_module


class GRAPH_SECURITY_SCORE_INPUT(smi.Script):

    def __init__(self):
        super(GRAPH_SECURITY_SCORE_INPUT, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('graph_security_score_input')
        scheme.description = 'Graph Security Score Input'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'azure_ad_tenant_id',
                required_on_create=True,
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'application_id',
                required_on_create=True,
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'client_secret',
                required_on_create=True,
            )
        )
        
        return scheme

    def validate_input(self, definition):
        input_module.validate_input(self, definition)

    def stream_events(self, inputs, ew):
        input_module.collect_events(self, ew)


if __name__ == '__main__':
    exit_code = GRAPH_SECURITY_SCORE_INPUT().run(sys.argv)
    sys.exit(exit_code)