// Excerpt of Wekan, models/boards.js (MIT License, Copyright (c) Lauri
// Ojansivu). Source: repo wekan/wekan, commit
// 196c56769bbe246933076038f150bc4929174477.

/**
 * Is supplied user authorized to view this board?
 */
isVisibleBy(user) {
  if (this.isPublic()) {
    // public boards are visible to everyone
    return true;
  } else {
    // otherwise you have to be logged-in and active member
    return user && this.isActiveMember(user._id);
  }
},

/**
 * Is the user one of the active members of the board?
 *
 * @param userId
 * @returns {boolean} the member that matches, or undefined/false
 */
isActiveMember(userId) {
  if (userId) {
    return this.members.find(
      member => member.userId === userId && member.isActive,
    );
  } else {
    return false;
  }
},
