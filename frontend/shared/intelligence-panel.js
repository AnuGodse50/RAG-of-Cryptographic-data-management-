class IntelligencePanel {
    constructor(containerId, caseId) {
        this.container = document.getElementById(containerId);
        this.caseId = caseId;
        this.render();
    }
    render() {
        this.container.innerHTML = \
            <div class="chat-container">
                <div class="chat-messages" id="chatMessages">
                    <div class="msg ai">Hello. I am the Case Assistant (RAG). I can analyze the records and laws for this case.</div>
                </div>
                <div class="chat-input">
                    <input type="text" id="chatInput" placeholder="Ask about this case or legal provisions...">
                    <button class="btn btn-primary" id="chatSend">Ask</button>
                </div>
            </div>
        \;
        document.getElementById('chatSend').addEventListener('click', () => this.sendMessage());
        document.getElementById('chatInput').addEventListener('keypress', (e) => { if(e.key === 'Enter') this.sendMessage(); });
    }
    async sendMessage() {
        const input = document.getElementById('chatInput');
        const text = input.value.trim();
        if(!text) return;
        
        this.addMessage(text, 'user');
        input.value = '';
        
        const loader = this.addMessage('Analyzing encrypted chunks and legal corpus...', 'ai');
        
        try {
            await new Promise(r => setTimeout(r, 1200));
            loader.remove();
            
            const responseText = "Based on the retrieved documents, the charge under BNS §304 (Snatching) requires proof of theft with sudden force. The FIR states the victim was pushed.";
            const citation = "FIR-1234, BNS §304";
            
            const msgEl = this.addMessage(responseText, 'ai');
            const citEl = document.createElement('div');
            citEl.className = 'citation';
            citEl.textContent = 'Source: ' + citation;
            msgEl.appendChild(citEl);
            
        } catch(e) {
            loader.remove();
            this.addMessage('Error communicating with Case Assistant.', 'ai');
        }
    }
    addMessage(text, role) {
        const messages = document.getElementById('chatMessages');
        const msg = document.createElement('div');
        msg.className = 'msg ' + role;
        msg.textContent = text;
        messages.appendChild(msg);
        messages.scrollTop = messages.scrollHeight;
        return msg;
    }
}
window.IntelligencePanel = IntelligencePanel;
