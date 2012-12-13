package de.uni.trier.infsec.tools.envgen;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.HashMap;

import de.uni.trier.infsec.tools.envgen.SystemInterface.ClassInterface;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Exception;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Field;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Method;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Parameter;

public class ConditionVerifier {

	private HashMap<String, String> acceptedTypes = new HashMap<>();
	private HashMap<String, String> primitiveTypes = new HashMap<>();

	public ConditionVerifier(SystemInterface system, String acceptedTypesFile) {
		
		if (acceptedTypesFile != null) {			
			try {
				File f = new File(acceptedTypesFile);
				if (f.exists()) {
					BufferedReader br = new BufferedReader(new FileReader(f));
					StringBuffer sb = new StringBuffer();
					while (br.ready()) sb.append(br.readLine());
					br.close();
					
					for (String aType : sb.toString().split(",")) {					
						acceptedTypes.put(aType, null);
					}
				}
			} catch (IOException e) {
				System.err.println("AcceptedTypes List could not be read: " + e.getMessage());
			}
		}
		
		for (ClassInterface c : system.classes) {
			acceptedTypes.put(c.name, null);
		}
		primitiveTypes.put("int", null);
		primitiveTypes.put("byte[]", null);
		primitiveTypes.put("void", null);
		primitiveTypes.put("byte", null);

		for (String s : primitiveTypes.keySet())
			System.out.println(String.format("%s is primitive type", s));
		for (String s : acceptedTypes.keySet())
			System.out.println(String.format("%s is accepted type", s));
	}

	public boolean verifyConditions(SystemInterface si) {

		// Appendix D.A, Point 1
		// Methods of classes in IE are static (constructors are not in IE). Their arguments are of primitive types or of type
		// byte[]. These methods may return values of primitive types, of type byte[], or objects of predefined classes
		// and classes defined in IE. These methods can throw exceptions of predefined classes and of classes defined in IE.

		// TODO: open problem is to find out the fully qualified name of parameter and field classes! (import abc.def.* etc)

		for (ClassInterface ci : si.classes) {
			
			for (String type : ci.extendList) {
				if (!acceptedType(type)) {
					System.err.println(MessageFormat.format("{0} extends unsupported type {1}", ci.name, type));
					return false;
				}
			}
			for (Method m : ci.methods) {
				if (!m.isStatic) {
					System.err.println(MessageFormat.format("There is a non-static method: {0} in class {1}", m.toString(), ci.name));
					return false;
				}
				for (Parameter p : m.parameters) {
					String type = ci.importMap.get(p.type) != null ? ci.importMap.get(p.type) : p.type;
					if (!acceptedType(type)) {
						System.err.println(MessageFormat.format("Parameter [{0}] from [{1}] has unsupported type", p.toString(), m.toString()));
						return false;
					}
				}
				String type = ci.importMap.get(m.type) != null ? ci.importMap.get(m.type) : m.type;
				if (!acceptedType(type)) {
					System.err.println(MessageFormat.format("Return type of Method [{0}] is unsupported", m.toString()));
					return false;
				}
				for (Exception e : m.exceptions) {
					type = ci.importMap.get(e.name) != null ? ci.importMap.get(e.name) : e.name;
					if (!acceptedType(type)) {
						System.err.println(MessageFormat.format("Exception [{0}] from [{1}] has unsupported type", e.toString(), m.toString()));
						return false;
					}
				}
			}

			// Appendix D.A, Point 2
			// Fields of classes in IE are non-static and of primitive types or of type byte[]

			for (Field f : ci.fields) {
				if (f.isStatic) {
					System.err.println(MessageFormat.format("There is a static field: {0}", f.toString()));
					return false;
				}
				if (!primitiveType(f.type)) {
					System.err.println(MessageFormat.format("Type of field [{0}] is not primitive", f.toString()));
					return false;
				}
			}

			if (!ci.constructors.isEmpty()) {
				System.err.println(MessageFormat.format("Class {0} contains a constructor!", ci.name));
				return false;
			}
		}
		return true;
	}

	private boolean acceptedType(String type) {
		return acceptedTypes.containsKey(type) || primitiveType(type);
	}

	private boolean primitiveType(String type) {
		return primitiveTypes.containsKey(type);
	}

}
