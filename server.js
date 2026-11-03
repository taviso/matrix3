import { MessageTypes } from '/include/commands.js'

export default class RequestServer {
    tracker;

    constructor(tracker) {
        this.tracker = tracker;
        chrome.runtime.onMessage.addListener(this.messageHandler.bind(this));
    }

    messageHandler(request, sender, sendResponse) {
        switch (request.command) {
            case MessageTypes.REQ_POLICY:
                this.tracker.getDirectives(request.data.id, request.data.domain).then(sendResponse);
                return true;
            case MessageTypes.REQ_HEADERS:
                this.tracker.getServerPolicy(request.data.id, request.data.domain).then(sendResponse);
                return true;
        }
    }
}
