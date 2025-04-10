package pt.unl.fct.di.apdc.firstwebapp.util;

public class UserCreationInfo {
    public String email,username,name,phone,password, passwordConfirm,perfil,cc,role,nif,employee,function,address,nifEmp,status,photo;

    public UserCreationInfo(){}


    public boolean isValid(){
        return isEmailValid() && username != null && name != null && phone != null && isPasswordValid() && isPerfilValid();
    }

    private boolean isEmailValid(){
        return email != null && email.matches("^[^@\\s]+@([^.@\\s]+\\.)+[^.@\\s]{2,}$");
    }

    private boolean isPasswordValid(){
        return password != null && password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).{8,}$") && password.equals(passwordConfirm);
    }

    private boolean isPerfilValid(){
        return perfil != null && (perfil.equals("publico") || perfil.equals("privado"));
    }
}