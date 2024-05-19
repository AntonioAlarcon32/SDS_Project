from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

class CustomEndpointRyuApp(app_manager.RyuApp):
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(CustomEndpointRyuApp, self).__init__(*args, **kwargs)
        self.wsgi = kwargs['wsgi']
        self.data = {}
        self.data['custom_app'] = self
        mapper = self.wsgi.mapper
        wsgi_app = self.wsgi

        mapper.connect('activate-honeypot', '/activate-honeypot',
                       controller=CustomController, action='activate_honeypot',
                       conditions=dict(method=['GET']))
        mapper.connect('deactivate-honeypot', '/deactivate-honeypot',
                       controller=CustomController, action='deactivate_honeypot',
                       conditions=dict(method=['GET']))

        mapper.connect('test', '/test',
                       controller=CustomController, action='test_function',
                       conditions=dict(method=['GET']))
        wsgi_app.registory['CustomController'] = self.data

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info('Switch connected: %s', ev.msg.datapath.id)

class CustomController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(CustomController, self).__init__(req, link, data, **config)
        self.custom_app = data['custom_app']

    @route('activate-honeypot', '/activate-honeypot', methods=['GET'])
    def activate_honeypot(self, req, **kwargs):
        custom_app = self.custom_app
        body = b'{"message": "Hello from custom endpoint!"}'
        return Response(content_type='application/json', body=body)

    @route('deactivate-honeypot', '/deactivate-honeypot', methods=['GET'])
    def deactivate_honeypot(self, req, **kwargs):
        custom_app = self.custom_app
        body = b'{"message": "Hello from custom endpoint!"}'
        return Response(content_type='application/json', body=body)

    @route('test', '/test', methods=['GET'])
    def test_function(self, req, **kwargs):
        custom_app = self.custom_app
        body = b'{"message": "This ryu controller is reachable"}'
        return Response(content_type='application/json', body=body)

