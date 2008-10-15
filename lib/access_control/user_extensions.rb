module AccessControl
  module UserExtensions
    def can_access?(object)
      return true if superadmin?
      case object
      when Project
        activated? && (object.users.include?(self) || object.company.is_admin?(self))
      when Company
        object.users.include?(self)
      when Page
        can_access?(object.project) && (object.public? || object.company.users.include?(self))
      when Folder
        can_access?(object.project) && (object.public? || object.project.company.users.include?(self))
      else
        false
      end
    end
  
    def can_write?(object)
      return true if superadmin?
      case object
      when Project
        activated? && object.company.is_admin?(self)
      when Company
        object.is_admin?(self)
      when Page
        can_access?(object.project) && (object.public? || object.company.users.include?(self))
      when Folder
        can_access?(object.project) && (object.public? || object.project.company.users.include?(self))
      end
    end
  end
end