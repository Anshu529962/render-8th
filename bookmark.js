console.log('📚 Bookmark JavaScript loaded successfully!');

function toggleBookmark(questionId, subject, topic) {
    console.log('🔄 Bookmark toggle called:', questionId, subject, topic);
    
    const bookmarkBtn = document.getElementById('bookmark-btn');
    if (!bookmarkBtn) {
        console.error('❌ Bookmark button not found!');
        return;
    }
    
    const originalText = bookmarkBtn.innerHTML;
    
    // Show loading state
    bookmarkBtn.innerHTML = '⏳ Loading...';
    bookmarkBtn.disabled = true;

    fetch('/toggle_bookmark', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            question_id: questionId,
            subject: subject,
            topic: topic
        })
    })
    .then(response => {
        console.log('📡 Response status:', response.status);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('📄 Response data:', data);
        
        if (data.success) {
            // Update bookmark button state
            if (data.bookmarked) {
                bookmarkBtn.classList.add('bookmarked');
                console.log('✅ Bookmark added');
            } else {
                bookmarkBtn.classList.remove('bookmarked');
                console.log('✅ Bookmark removed');
            }
            
            // Restore star icon
            bookmarkBtn.innerHTML = '★';
            
            // Optional: Show success message
            showBookmarkMessage(data.message, 'success');
        } else {
            // Restore original state on error
            bookmarkBtn.innerHTML = originalText;
            showBookmarkMessage(data.message || 'Bookmark operation failed', 'error');
        }
    })
    .catch(error => {
        console.error('❌ Bookmark error:', error);
        bookmarkBtn.innerHTML = originalText;
        showBookmarkMessage('Network error occurred', 'error');
    })
    .finally(() => {
        bookmarkBtn.disabled = false;
    });
}

function showBookmarkMessage(message, type) {
    // Remove existing messages
    const existingMessages = document.querySelectorAll('.bookmark-message');
    existingMessages.forEach(msg => msg.remove());
    
    // Create new message
    const messageDiv = document.createElement('div');
    messageDiv.textContent = message;
    messageDiv.className = `bookmark-message ${type}`;
    messageDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 6px;
        color: white;
        z-index: 1000;
        font-weight: 500;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        ${type === 'success' ? 'background-color: #28a745;' : 'background-color: #dc3545;'}
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(messageDiv);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (messageDiv.parentNode) {
            messageDiv.remove();
        }
    }, 3000);
}

console.log('✅ Bookmark functionality initialized');
