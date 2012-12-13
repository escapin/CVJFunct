package de.uni.trier.infsec.tools.envgen;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class SystemInterface {
	
	public ArrayList<ClassInterface> classes = new ArrayList<>();
	public String mainPackage = null;

	@Override
	public String toString() {
		StringBuffer out = new StringBuffer();
		for (ClassInterface ci : classes) {
			out.append(ci.toString());
			out.append("\n\n");
		}
		return out.toString();
	}
	
	public static class ClassInterface {
		public String name = null;
		public String packageName = null;
		public boolean isStatic = false;
		public boolean isInterface = false;
		public String visibility = "";
		
		public ArrayList<String> extendList = new ArrayList<String>();
		public ArrayList<String> imports = new ArrayList<>();
	
		public ArrayList<Constructor> constructors = new ArrayList<>();
		public ArrayList<Method> methods = new ArrayList<>();
		public ArrayList<Field> fields = new ArrayList<>();
		
		// This map is used to remember which class has been imported from which package. 
		public HashMap<String, String> importMap = null;
		
		@Override
		public String toString() {
			StringBuffer out = new StringBuffer("/* This class has been automatically generated */\n");
			
			if (packageName != null && !packageName.equals("")) {
				out.append(String.format("package %s;\n\n", packageName));
			}
			
			for (String importString : imports) {
				out.append(String.format("import %s;\n", importString));
			}
			
			// Generate class declaration
			out.append(String.format("%s %s class %s", visibility, isStatic ? "static " : "", name));
			
			// Now append all extends separated by comma
			if (!extendList.isEmpty()) {
				out.append(" extends ");
				Iterator<String> iter = extendList.iterator();
				out.append(iter.next()); // list not empty, so we have >= 1
				while (iter.hasNext()) out.append(", " + iter.next());
			}
			
			// declaration if complete, now add the class body
			out.append(" {\n\n");
			
			for (Constructor c : constructors) out.append("\t" + c.toString());
			for (Method m : methods) out.append("\t" + m.toString() + "\n");
			for (Field f : fields) out.append("\t" + f.toString() + "\n");
			
			out.append("}");
			return out.toString();
		}
	}
	
	public static class Constructor {
		public ArrayList<Parameter> parameters = new ArrayList<>();
		public ArrayList<Exception> exceptions = new ArrayList<>();
		public String name;
		public String visibility = "";
		
		public Constructor(String name) {
			this.name = name;
		}
		
		@Override
		public String toString() {
			// Build parameter String and create method signature
			StringBuilder out = new StringBuilder();
			for (Parameter p : parameters) {
				if (out.length() > 0) out.append(", ");
				out.append(p.toString());
			}
			
			return String.format("%s %s(%s) {}\n\n", visibility, name, out);
		}
	}
	
	public static class Method {
		
		public Method(String type, String name) {
			this.type = type;
			this.name = name;
		}
		
		public String type = "";
		public String name = "";
		public String body = "";
		
		public ArrayList<Exception> exceptions = new ArrayList<>();
		public ArrayList<Parameter> parameters = new ArrayList<>();
		public String visibility = "";
		public boolean isStatic = false;
		
		@Override
		public String toString() {
			StringBuffer out = new StringBuffer();
			// Message signature
			out.append(String.format("%s %s %s %s", visibility, isStatic ? "static " : "", type, name));
			
			// Append all parameters
			StringBuffer tmp = new StringBuffer();
			for (Parameter p : parameters) {
				if (tmp.length() > 0) tmp.append(", ");
				tmp.append(p.toString());
			}
			out.append(String.format("(%s)", tmp.toString()));
			
			// and in case of exceptions append the throws block
			tmp = new StringBuffer();
			for (Exception e : exceptions){
				if (tmp.length() > 0) tmp.append(", ");
				tmp.append(e.toString());
			}
			out.append(tmp.length() > 0 ? String.format(" throws %s", tmp.toString()) : "");
			out.append(" {");
			// Last but not least append the body
			out.append(String.format("\n%s\n\t}\n", body));
			
			return out.toString();
		}
	}
	
	public static class Field {

		public String type = "";
		public String name = "";
		public String visibility = "";
		public boolean isStatic = false;
		//TODO More modifiers needed? (volatile, synchronized...)
		
		public Field(String type, String name) {
			this.type = type;
			this.name = name;
		}
		
		@Override
		public String toString() {
			return String.format("%s %s %s %s;", visibility, isStatic ? "static" : "", type, name);
		}
	}
	
	public static class Parameter {
		public String type = "";
		public String name = "";

		public Parameter(String type, String name) {
			this.type = type;
			this.name = name;
		}
		
		@Override
		public String toString() {
			return type + " " + name;
		}
	}

	public static class Exception {
		public String name = "";
		
		public Exception (String name) {
			this.name = name;
		}
		
		@Override
		public String toString() {
			return name;
		}
	}
}

