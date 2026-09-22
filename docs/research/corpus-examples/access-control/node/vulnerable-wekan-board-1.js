// Manufactured vulnerable variant, derived from
// idiomatic-wekan-board-1.js (Wekan, MIT License). Illustrates a common
// real-world anti-pattern: a later-added API/REST endpoint that fetches a
// board directly by ID and returns it, without calling the board's own
// isVisibleBy()/isActiveMember() membership check the idiomatic side
// defines -- an IDOR/BOLA on the board's object reference (CWE-639/862).
JsonRoutes.add('GET', '/api/boards/:boardId', function (req, res) {
  const boardId = req.params.boardId;

  // No isVisibleBy(req.userId) / isActiveMember(req.userId) check here:
  // any authenticated (or, depending on the wrapping middleware, any
  // unauthenticated) caller who knows/guesses a boardId gets the full
  // board document back, public or private, member or not.
  const board = Boards.findOne({ _id: boardId });

  JsonRoutes.sendResult(res, {
    code: 200,
    data: board,
  });
});
