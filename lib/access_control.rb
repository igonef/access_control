module AccessControl
  class AccessError < Exception; end
  class NoUserError < AccessError; end
  class AccessDenied < AccessError; end
end