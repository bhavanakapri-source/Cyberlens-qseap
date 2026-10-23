import { useEffect, useState } from "react";

import Sidebar from "./components/Sidebar.jsx";
import ChatWindow from "./components/ChatWindow.jsx";
import Auth from "./components/Auth.jsx";

import "./App.css";

const API_URL =os.getenv("HUGGING_FACE_API");

function App() {
  const [user, setUser] = useState(() => {
    const savedUser =
      localStorage.getItem("cyberlens_user");

    const savedToken =
      localStorage.getItem("cyberlens_token");

    // User is authenticated only when BOTH exist.
    if (!savedUser || !savedToken) {
      return null;
    }

    try {
      return JSON.parse(savedUser);
    } catch {
      localStorage.removeItem("cyberlens_user");
      localStorage.removeItem("cyberlens_token");
      return null;
    }
  });

  const [conversations, setConversations] =
    useState([]);

  const [currentConversationId, setCurrentConversationId] =
    useState(null);

  const [messages, setMessages] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  const [notice, setNotice] =
    useState("");

  const [sidebarOpen, setSidebarOpen] =
    useState(false);

  const token =
    localStorage.getItem("cyberlens_token");

  const logout = (expired = false) => {
    setNotice(
      expired === true
        ? "Your session has expired. Please log in again."
        : ""
    );

    setSidebarOpen(false);

    localStorage.removeItem(
      "cyberlens_token"
    );

    localStorage.removeItem(
      "cyberlens_user"
    );

    setUser(null);
    setConversations([]);
    setMessages([]);
    setCurrentConversationId(null);
  };

  const authHeaders = () => ({
    Authorization: `Bearer ${localStorage.getItem(
      "cyberlens_token"
    )}`,
  });

  const loadConversations = async () => {
    try {
      const response = await fetch(
        `${API_URL}/api/conversations`,
        {
          headers: authHeaders(),
        }
      );

      if (response.status === 401) {
        logout(true);
        return;
      }

      if (!response.ok) {
        throw new Error(
          "Failed to load conversations."
        );
      }

      const data = await response.json();

      setConversations(data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") {
        setSidebarOpen(false);
      }
    };

    window.addEventListener(
      "keydown",
      onKey
    );

    return () =>
      window.removeEventListener(
        "keydown",
        onKey
      );
  }, []);

  useEffect(() => {
    if (user && token) {
      loadConversations();
    }
  }, [user, token]);

  const handleLogin = (loggedInUser) => {
    setNotice("");
    setUser(loggedInUser);
  };

  const newChat = () => {
    setSidebarOpen(false);
    setCurrentConversationId(null);
    setMessages([]);
  };

  const selectConversation = async (
    conversationId
  ) => {
    try {
      const response = await fetch(
        `${API_URL}/api/conversations/${conversationId}/messages`,
        {
          headers: authHeaders(),
        }
      );

      if (response.status === 401) {
        logout(true);
        return;
      }

      if (!response.ok) {
        throw new Error(
          "Failed to load conversation."
        );
      }

      const data = await response.json();

      setCurrentConversationId(
        conversationId
      );

      setMessages(data);
      setSidebarOpen(false);
    } catch (error) {
      console.error(error);
    }
  };

  const sendMessage = async (query) => {
    if (!query.trim() || loading) {
      return;
    }

    const temporaryUserMessage = {
      id: `temp-${Date.now()}`,
      role: "user",
      content: query,
    };

    setMessages((previous) => [
      ...previous,
      temporaryUserMessage,
    ]);

    setLoading(true);

    try {
      const response = await fetch(
        `${API_URL}/api/query`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${localStorage.getItem(
                "cyberlens_token"
              )}`,
          },

          body: JSON.stringify({
            query,
            conversation_id:
              currentConversationId,
          }),
        }
      );

      if (response.status === 401) {
        logout(true);
        return;
      }

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Failed to get response."
        );
      }

      setCurrentConversationId(
        data.conversation_id
      );

      setMessages((previous) => [
        ...previous,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: data.answer,
        },
      ]);

      await loadConversations();

    } catch (error) {
      console.error(error);

      setMessages((previous) => [
        ...previous,
        {
          id: `error-${Date.now()}`,
          role: "assistant",
          isError: true,
          content:
            error instanceof TypeError
              ? "Unable to connect to CyberLens. Please check that the backend is running."
              : "CyberLens couldn't complete that request. Please try again.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  // IMPORTANT:
  // No token = no authenticated session.
  if (!user || !token) {
    return (
      <Auth
        onLogin={handleLogin}
        notice={notice}
      />
    );
  }

  return (
    <div className="app">
      <Sidebar
        conversations={conversations}
        currentConversationId={
          currentConversationId
        }
        onNewChat={newChat}
        onSelectConversation={
          selectConversation
        }
        user={user}
        onLogout={() => logout()}
        open={sidebarOpen}
        onClose={() =>
          setSidebarOpen(false)
        }
      />

      {sidebarOpen && (
        <div
          className="sidebar-backdrop"
          onClick={() =>
            setSidebarOpen(false)
          }
          aria-hidden="true"
        />
      )}

      <ChatWindow
        title={
          conversations.find(
            (c) =>
              c.id ===
              currentConversationId
          )?.title
        }
        user={user}
        messages={messages}
        loading={loading}
        onSend={sendMessage}
        onMenu={() =>
          setSidebarOpen(true)
        }
      />
    </div>
  );
}

export default App;