module AccessControl
  module ObjectAccess
    ROLES = [:anonymous, :guest, :external, :user, :admin, :superadmin]
    
    def read
    end
    
    # :nodoc:
    # Метод перекрывает method_missing и на лету по первому запросу генерит
    # прокси методы safe_my_method_name
    def method_missing_with_object_access_check(method_name, *args)
      if safe_method = method_name.to_s[/^safe_(.+)/, 1]
        generate_safe_access_method(safe_method)
        send(method_name, *args)
      elsif can_method = method_name.to_s[/^can_(.+)/, 1]
        generate_verify_access_method(can_method)
        send(method_name, *args)
      else
        method_missing_without_object_access_check(method_name, *args)
      end
    end
    
    # :nodoc:
    # Метод занимается одноразовой генерацией удостоверивающегося прокси
    def generate_safe_access_method(missed_method)
      required_role = require_role_for(missed_method)
      required_level = ROLES.index(required_role).to_i
      self.class.class_eval <<-EOF, __FILE__+":safe_#{missed_method}", __LINE__
      def safe_#{missed_method}(*args)
        raise AccessControl::NoUserError if args.length == 0
        check_access_level!(:#{missed_method}, #{required_level}, args.pop)
        #{missed_method}(*args)
      end
      EOF
    end
    
    def generate_verify_access_method(missed_method)
      required_role = require_role_for(missed_method)
      required_level = ROLES.index(required_role).to_i
      self.class.class_eval <<-EOF, __FILE__+":can_#{missed_method}", __LINE__
      def can_#{missed_method}(*args)
        raise AccessControl::NoUserError if args.length == 0
        verify_access_level(:#{missed_method}, #{required_level}, args.pop)
      end
      EOF
    end
    
    def log_access(user, method, level, required_level)
      role = ROLES[level]
      required = ROLES[required_level]
      logger.info "ACL: user #{user.id} requested #{self.class}##{self.id}.#{method} with role #{role}. Required: #{required}"
    end
    
    # :nodoc:
    # внутренний метод, который начинает вычислять роль пришедшего пользователя
    def __find_user_role(user)
      return :anonymous unless user
      return :superadmin if user.respond_to?(:superadmin?) && user.superadmin?
      user_role(user)
    end
    
    # This method can be overwritten in your code. Returns role of visitor on current object
    def user_role(user)
      :guest
    end
    
    # :nodoc:
    # вычисляет уровень доступа пришедшего пользователя
    def user_access_level(user)
      ROLES.index(__find_user_role(user)).to_i
    end
    
    def verify_access_level(method, required_level, user)
      level = user_access_level(user)
      log_access(user, method, level, required_level)
      level >= required_level
    end
    
    # :nodoc:
    # выполняет проверку на уровень доступа
    def check_access_level!(method, required_level, user)
      level = user_access_level(user)
      log_access(user, method, level, required_level)
      raise AccessDenied if level < required_level
      level
    end

    # Tell, what lowerest role is required to perform this action
    def require_role_for(method_name)
      :anonymous
    end
    
    def safe_update_attributes(params, user)
      level = check_access_level!(:update_attributes, :guest, args.pop)
      allowed_params = (0..level).map {|i| allowed_model_params_for(ROLES[i]) }.reject {|p| p.nil?}
      return update_attributes(params) if allowed_params.blank?
      update_attributes(params.slice(*allowed_params.flatten.uniq))
    end
    
    def self.included(base)
      base.instance_eval do
        extend ObjectAccess
        extend ClassMethods
        alias_method_chain :method_missing, :object_access_check
      end
      alias_method_chain :method_missing, :object_access_check
    end
    
    def allowed_model_params_for(role)
    end
    
    module ClassMethods
      def safe_find(id, user)
        find(id)
      end
      
      def safe_new(params, user)
        new(params)
      end      
    end
  end
end