document.addEventListener('DOMContentLoaded', () => {
    const chatHistory = document.getElementById('chat-history');
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');
  
    // Load chat history when the page loads
    fetchChatHistory();
  
    // Send message on button click
    sendButton.addEventListener('click', sendMessage);
  
    // Send message on Enter key press
    userInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        sendMessage();
      }
    });
  
    function sendMessage() {
      const message = userInput.value.trim();
      if (!message) return;
  
      // Display user message
      appendMessage('user', message);
      userInput.value = '';
  
      // Send message to backend
      fetch('/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message }),
      })
        .then(response => response.json())
        .then(data => {
          // Display bot response
          appendMessage('bot', data.response);
          // Scroll to bottom
          chatHistory.scrollTop = chatHistory.scrollHeight;
        })
        .catch(error => {
          console.error('Error:', error);
          appendMessage('bot', 'Error: Could not get a response. Please try again.');
        });
    }
  
    function appendMessage(sender, message) {
      const messageDiv = document.createElement('div');
      messageDiv.className = `chat-message ${sender}`;
      
      // Add icon and message content
      const icon = sender === 'user' ? '<i class="fas fa-user"></i>' : '<i class="fas fa-robot"></i>';
      messageDiv.innerHTML = `${icon} ${message}`;
      
      chatHistory.appendChild(messageDiv);
      chatHistory.scrollTop = chatHistory.scrollHeight;
    }
  
    function fetchChatHistory() {
      fetch('/chat_history')
        .then(response => response.json())
        .then(data => {
          data.forEach(chat => {
            appendMessage('user', chat.user_message);
            appendMessage('bot', chat.bot_response);
          });
        })
        .catch(error => {
          console.error('Error fetching chat history:', error);
        });
    }
  });