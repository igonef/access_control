require 'access_control'

ActiveRecord::Base.class_eval do
  include AccessControl::ObjectAccess
end
