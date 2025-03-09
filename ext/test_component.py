from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class MyComponent(object):
	def __init__(self):
		core.openflow.addListeners(self)
		log.info("MyComponenet initialized")
	def handle_ConnectionUp(self, event):
		log.info("Switch connected with dpid: %s", event.dpid)

def launch():
	core.registerNew(MyComponent)
