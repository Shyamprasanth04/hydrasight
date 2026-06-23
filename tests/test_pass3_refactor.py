from hydrasight.core.builtin_actions import register_builtins
from hydrasight.services.action_planner import ActionPlanner
from hydrasight.services.dispatcher import Dispatcher
from hydrasight.services.intent_classifier import Intent, IntentClassifier
from hydrasight.services.intent_router import route_intent

# Ensure registry is populated for tests
register_builtins()

def test_nl_phrase_to_correct_action_id():
    classifier = IntentClassifier()

    res = classifier.classify("scan 10.10.10.10")
    assert res.intent == Intent.EXECUTE_ACTION
    assert res.tool_hint == "nmap_scan"

    res2 = classifier.classify("check ftp on 192.168.1.1")
    assert res2.tool_hint == "ftp_check"

def test_smb_routing_priority():
    classifier = IntentClassifier()

    # 1. smbclient > share enumeration
    res1 = classifier.classify("smbclient 10.0.0.1")
    assert res1.tool_hint == "smbclient_enum"

    # 2. smb enum > smb check
    res2 = classifier.classify("enumerate smb shares on 10.0.0.1")
    assert res2.tool_hint == "smb_enum"

    # 3. smb check > vuln scan
    res3 = classifier.classify("smb vuln scan 10.0.0.1")
    assert res3.tool_hint == "smb_check"

def test_route_intent_registry_backed():
    # nmap_smb_vuln routes to smb_check
    res = route_intent("smb vuln ms17", "10.0.0.1")
    assert res is not None
    assert res["tool"] == "smb_check"
    assert res["args"]["target"] == "10.0.0.1"

    res2 = route_intent("enum4linux", "10.0.0.1")
    assert res2 is not None
    assert res2["tool"] == "smb_enum"

def test_planner_output_uses_registry_defaults():
    classifier = IntentClassifier()
    planner = ActionPlanner()

    res = classifier.classify("scan 10.10.10.10")
    action = planner.plan(res)

    assert action is not None
    assert action.request.action_id == "nmap_scan"
    assert action.request.target == "10.10.10.10"

    # Check that CommandSpec is built safely
    assert action.spec.executable == "nmap"
    args = [arg.value for arg in action.spec.args]
    assert "-sV" in args
    assert "-sC" in args
    assert "10.10.10.10" in args

from hydrasight.integrations.kali_api import KaliAPI

class MockKaliAPI(KaliAPI):
    def __init__(self):
        self.last_cmd = ""
    def run(self, cmd, timeout=0):
        self.last_cmd = cmd
        return {"output": "ok", "success": True}
    def local_ip(self, target):
        return "127.0.0.1"

def test_dispatcher_uses_command_builder():
    kali = MockKaliAPI()
    import logging
    log = logging.getLogger("test")
    dispatcher = Dispatcher(kali, log, {})

    classifier = IntentClassifier()
    planner = ActionPlanner()

    # smbclient_enum has pipe and truncation logic
    res = classifier.classify("smbclient 10.10.10.10")
    action = planner.plan(res)
    assert action is not None

    tool, output, elapsed = dispatcher.dispatch(action)

    assert tool == "smbclient_enum"
    # The rendered command via CommandBuilder shouldn't have '21' fragment
    assert " 21 " not in kali.last_cmd
    assert kali.last_cmd.endswith("2>&1 | head -n 40")

def test_malformed_fragments_regression():
    kali = MockKaliAPI()
    import logging
    log = logging.getLogger("test")
    dispatcher = Dispatcher(kali, log, {})

    # Legacy string builder test case - ensure it goes through CommandBuilder safely
    # enum4linux -a 192.168.100.133
    res = IntentClassifier().classify("enumerate smb shares on 192.168.100.133")
    action = ActionPlanner().plan(res)
    assert action is not None

    dispatcher.dispatch(action)
    # Assert that even though tool=nmap_smb_vuln, the registry mapped it back to enum4linux
    # without retaining the old fragment.
    assert kali.last_cmd == "enum4linux -a 192.168.100.133 2>&1 | head -n 150"
    assert "21" not in kali.last_cmd

def test_execution_modes_preserved():
    # Confirm, auto, never logic is primarily handled in ChatController/ExecutionPolicy,
    # but let's ensure PendingAction has confidence and reason to support them.
    classifier = IntentClassifier()
    res = classifier.classify("run scan 10.0.0.1")
    assert res.intent == Intent.EXECUTE_ACTION
    assert res.confidence == 0.9  # exec verb + IP

    planner = ActionPlanner()
    action = planner.plan(res)
    assert action is not None
    assert action.confidence == 0.9

def test_existing_builtins_work():
    classifier = IntentClassifier()
    res = classifier.classify("verify findings")
    assert res.intent == Intent.VERIFY_FINDINGS

    res = classifier.classify("show conclusion")
    assert res.intent == Intent.SHOW_CONCLUSION

    res = classifier.classify("suggest next step")
    assert res.intent == Intent.SHOW_SUGGESTIONS
