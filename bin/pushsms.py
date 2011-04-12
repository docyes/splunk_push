# standard
import urllib
import urllib2
import base64
import sys
import os
import logging as logger
# package
import lxml.etree as et
# splunk
import splunk.entity
import splunk.Intersplunk
import splunk.util

logger.basicConfig(level=logger.INFO, format="%(asctime)s %(levelname)-s %(module)s:%(lineno)d - %(message)s",
                   filename=os.path.join(os.environ["SPLUNK_HOME"], "var", "log", "splunk", "push.log"),
                   filemode="a")

def twilio_settings(session_key, owner=None):
    settings = None
    try:
        settings = splunk.entity.getEntity('admin/conf-gateway', 'twilio', namespace='push', owner=owner, sessionKey=session_key)
    except Exception as e:
        logger.error(e)
    return settings

def twilio_send(to_number, from_number, message, account_sid, auth_token):
    """Post a sms message using the twilio REST API.
    Connection errors are log formatted and sent to standard out.
    to_number: The destination phone number. Format with a '+' and country code e.g., +16175551212 (E.164 format). 
    Twilio will also accept unformatted US numbers e.g., (415) 555-1212, 415-555-1212.
    from_number: A Twilio number enabled for SMS. Only phone numbers purchased from Twilio work here; you cannot (for example) spoof SMS messages from your own cell phone number.
    message: The text of the message you want to send, limited to 160 characters.
    account_sid: See https://www.twilio.com/user/account/
    auth_token: See https://www.twilio.com/user/account/
    """
    url = "https://api.twilio.com/2010-04-01/Accounts/%s/SMS/Messages" % account_sid
    max_len = 160
    message = str(message)
    if len(message) > max_len:
        logger.warn('gateway="twilio" message="truncating message, greater than max length constraint of %s"' % max_len)
        message = splunk.util.smartTrim(message, max_len)
    data = urllib.urlencode({"From": from_number, "To": to_number, "Body": message})
    request = urllib2.Request(url, data=data)
    base64string = base64.encodestring('%s:%s' % (account_sid, auth_token)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % base64string)
    logger.info('gateway="twilio" message="attempt to send sms to %s from %s with message %s"' % (to_number, from_number, message))
    try:
        response = urllib2.urlopen(request)
    except urllib2.HTTPError as e:
        raw = e.read()
        raw_xml = raw_xml_tidy(raw)
        logger.error('gateway="twilio" request_uri="%s" request_body="%s" message="server could not fullfill the request" code="%s" response="\n%s"' % (request.get_full_url(), data, e.code, raw_xml))
        more_info = twilio_more_info_xml_parser(raw)
        return False, more_info
    except urllib2.URLError as e:
        logger.error('gateway="twilio" resource_uri="%s" request_body="%s"  message="failed to connect to server" code="%s" response="%s"' % (request.get_full_url(), data, e.reason[0], e.reason[1]))
        return False, ''
    else:
        raw_xml = raw_xml_tidy(response.read())
        logger.info('gateway="twilio" resource_uri="%s" request_body="%s" message="successfully sent" from_number="%s" to_number="%s" response="%s"' % (request.get_full_url(), data, from_number, to_number, raw_xml))
        return True, ''

def twilio_more_info_xml_parser(raw):
    xml = None
    message = None
    try:
        xml = et.fromstring(raw)
    except Exception:
        pass
    if xml is not None:
        nodes = xml.xpath("//RestException/MoreInfo")
        if len(nodes)>0:
           message = nodes[0].text
    return message

def raw_xml_tidy(raw):
    tidy = ''
    try:
        xml = et.fromstring(raw)
        tidy = et.tostring(xml, pretty_print=True)
    except Exception:
        pass
    return tidy

def cmd_handler():
    messages = {}
    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
    results, legacy_results, settings = splunk.Intersplunk.getOrganizedResults()
    session_key = settings.get('sessionKey')
    owner = settings.get('owner')
    gateway_settings = twilio_settings(session_key, owner=owner)
    # validate gateway settings available
    if gateway_settings is None:
        message = "Could not retrieve gateway settings."
        logger.warn('command="sendsms" message="%s"' % message)
        splunk.Intersplunk.addWarnMessage(messages, message)
        splunk.Intersplunk.outputResults(results, messages=messages)
        return
    # validate account_sid
    account_sid = gateway_settings.get('account_sid')
    if account_sid is None:
        message = "Missing value 'account_sid' is not set."
        logger.warn('command="sendsms" message="%s"' % message)
        splunk.Intersplunk.addErrorMessage(messages, message)
        splunk.Intersplunk.outputResults(results, messages=messages)
        return
    # validate auth_token
    account_sid = gateway_settings.get('auth_token')
    if account_sid is None:
        message = "Missing value 'auth_token' is not set."
        logger.warn('command="sendsms" message="%s"' % message)
        splunk.Intersplunk.addErrorMessage(messages, message)
        splunk.Intersplunk.outputResults(results, messages=messages)
        return
    # validate to_number
    to_number = kwargs.get('to_number')
    if to_number is None:
        message = "Missing value 'to_number' is not set."
        logger.warn('command="sendsms" message="%s"' % message)
        splunk.Intersplunk.addErrorMessage(messages, message)
        splunk.Intersplunk.outputResults(results, messages=messages)
        return
    to_number = to_number.split(',')
    logger.info("---------------- to_number:%s" % to_number)
    # validate from_number
    from_number = gateway_settings.get('from_number')
    if from_number is None:
        message = "Missing value 'from_number' is not set."
        logger.warn('command="sendsms" message="%s"' % message)
        splunk.Intersplunk.addErrorMessage(messages, message)
        splunk.Intersplunk.outputResults(results, messages=messages)
        return
    # validate message
    message = kwargs.get('message')
    if message is None:
        message = "Missing value 'message' is not set."
        logger.warn('command="sendsms" message="%s"' % message)
        splunk.Intersplunk.addErrorMessage(messages, message)
        splunk.Intersplunk.outputResults(results, messages=messages)
        return
    # handle possible exception when using twilio gateway
    for number in to_number:
        try:
            is_sent, more_info = twilio_send(number, from_number, message, gateway_settings['account_sid'], gateway_settings['auth_token'])
        except Exception:
            message = "An unknown error occurred using the twilio gatway."
            logger.error('command="sendsms" message="%s"' % message)
            splunk.Intersplunk.addErrorMessage(messages, message)
            splunk.Intersplunk.outputResults(results, messages=messages)
            return
        else:
            if is_sent:
                continue
            else:
                message = "Could not successfully send an sms message to %s. See %s for more info." % (number, more_info)
                logger.error('command="sendsms" message="%s"' % message)
                splunk.Intersplunk.addErrorMessage(messages, message)
    # operation complete
    splunk.Intersplunk.outputResults(results, messages=messages)

if __name__ == '__main__':
    cmd_handler()
