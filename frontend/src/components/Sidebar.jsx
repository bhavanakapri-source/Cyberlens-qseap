import Logo from "./Logo";
import Icon from "./Icons";

function Sidebar({ conversations, currentConversationId, onNewChat, onSelectConversation, user, onLogout, open, onClose }) {
  const initial = (user?.name || user?.email || "?").trim().charAt(0).toUpperCase();

  return (
    <aside className={`sidebar ${open ? "open" : ""}`} aria-label="Investigations">
      <div className="sidebar-top">
        <div className="brand">
          <span className="brand-mark"><Logo size={22} /></span>
          <span className="brand-name">CyberLens</span>
          <button type="button" className="icon-button sidebar-close" onClick={onClose} aria-label="Close menu">
            <Icon name="close" />
          </button>
        </div>
        <button type="button" className="new-chat-button" onClick={onNewChat}>
          <Icon name="plus" size={17} /> New investigation
        </button>
      </div>

      <nav className="conversation-section" aria-label="Recent investigations">
        <div className="section-title">Recent investigations</div>
        <div className="conversation-list">
          {conversations.length === 0 ? (
            <div className="empty-conversations">Your investigations will appear here.</div>
          ) : (
            conversations.map((c) => (
              <button type="button" key={c.id} title={c.title}
                className={`conversation-item ${currentConversationId === c.id ? "active" : ""}`}
                aria-current={currentConversationId === c.id ? "page" : undefined}
                onClick={() => onSelectConversation(c.id)}>
                <Icon name="chat" size={15} />
                <span className="conversation-title">{c.title}</span>
              </button>
            ))
          )}
        </div>
      </nav>

      <div className="profile-card">
        <div className="user-avatar" aria-hidden="true">{initial}</div>
        <div className="user-details">
          <strong>{user?.name}</strong>
          <span>{user?.email}</span>
        </div>
        <button type="button" className="icon-button" onClick={onLogout} aria-label="Log out" title="Log out">
          <Icon name="logout" />
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;