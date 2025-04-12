const fs = require("fs");
const dbFile = "./users.json";

function clearUsers() {
  fs.writeFileSync(dbFile, JSON.stringify([], null, 2), "utf-8");
  console.log("Users database has been cleared.");
}

function loadUsers() {
  try {
    const data = fs.readFileSync(dbFile, "utf-8");
    return JSON.parse(data);
  } catch (error) {
    console.error("Error loading users:", error);
    return [];
  }
}

function saveUsers(users) {
  try {
    fs.writeFileSync(dbFile, JSON.stringify(users, null, 2), "utf-8");
  } catch (error) {
    console.error("Error saving users:", error);
  }
}

function addUser(username, email, password, role = null, roleId = null) {
  const users = loadUsers();

  if (users.some((user) => user.username === username)) {
    console.log("Username already exists!");
    return false;
  }

  const newUser = {
    id: users.length + 1,
    username,
    email,
    password,
    role,
    roleId,
  };

  users.push(newUser);
  saveUsers(users);
  return true;
}

module.exports = {
  clearUsers,
  loadUsers,
  saveUsers,
  addUser
};
