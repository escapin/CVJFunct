package de.uni.trier.infsec.tools.envgen;

import japa.parser.JavaParser;
import japa.parser.ParseException;
import japa.parser.ast.CompilationUnit;
import japa.parser.ast.ImportDeclaration;
import japa.parser.ast.body.ClassOrInterfaceDeclaration;
import japa.parser.ast.body.ConstructorDeclaration;
import japa.parser.ast.body.FieldDeclaration;
import japa.parser.ast.body.MethodDeclaration;
import japa.parser.ast.body.Parameter;
import japa.parser.ast.body.VariableDeclarator;
import japa.parser.ast.expr.NameExpr;
import japa.parser.ast.type.ClassOrInterfaceType;
import japa.parser.ast.visitor.GenericVisitorAdapter;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;

import de.uni.trier.infsec.tools.envgen.SystemInterface.ClassInterface;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Constructor;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Exception;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Field;
import de.uni.trier.infsec.tools.envgen.SystemInterface.Method;

public class InterfaceGenerator {

	@SuppressWarnings("unchecked")
	public ArrayList<ClassInterface> getInterfaceForCode(String code, SystemInterface si) throws UnsupportedEncodingException, ParseException {
		CompilationUnit compilation = JavaParser.parse(new ByteArrayInputStream(code.getBytes("UTF-8")));

		InterfaceGenerationVisitor visitor = new InterfaceGenerationVisitor();
		ArrayList<ClassInterface> theList = (ArrayList<ClassInterface>) visitor.visit(compilation, si);
		return theList;
	}

	@SuppressWarnings("rawtypes")
	public static class InterfaceGenerationVisitor extends GenericVisitorAdapter {
		SystemInterface out = new SystemInterface();
		String currentPackage = "";
		String currentClass = null;
		HashMap<String, String> classPackageMapping = new HashMap<>();

		@SuppressWarnings("unchecked")
		@Override
		public Object visit(CompilationUnit n, Object arg) {
			if (arg != null && arg instanceof SystemInterface)
				out = (SystemInterface) arg;

			currentPackage = n.getPackage().getName().toString();
			if (n.getImports() != null) {
				for (ImportDeclaration i : n.getImports()) {
					if (!i.getName().toString().contains("*")) {
						String s = i.getName().toString();
						classPackageMapping.put(s.substring(s.lastIndexOf(".") + 1, s.length()), s);
					}
				}
			}
			super.visit(n, null);
			return out;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Object visit(ClassOrInterfaceDeclaration n, Object arg) {
			ClassInterface current = new ClassInterface();
			current.packageName = currentPackage;
			currentClass = n.getName();
			current.name = n.getName();
			current.isInterface = Modifier.isInterface(n.getModifiers());
			current.visibility = getModifiersAsString(n.getModifiers());
			current.importMap = classPackageMapping;

			if (n.getExtends() != null) {
				for (ClassOrInterfaceType e : n.getExtends()) {
					current.extendList.add(e.getName());
				}
			}

			super.visit(n, current);
			out.classes.add(current);

			currentClass = currentClass.replace("." + n.getName(), "");
			currentPackage = currentPackage.replace("." + n.getName(), "");
			if (currentClass.equals(""))
				currentClass = null;

			return null;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Object visit(MethodDeclaration n, Object arg) {
			ClassInterface current = (ClassInterface) arg;
			Method theMethod = new Method(n.getType().toString(), n.getName());
			theMethod.isStatic = Modifier.isStatic(n.getModifiers());
			theMethod.visibility = getModifiersAsString(n.getModifiers());

			super.visit(n, current);

			if (n.getParameters() != null) {
				for (Parameter p : n.getParameters()) {
					theMethod.parameters.add(new de.uni.trier.infsec.tools.envgen.SystemInterface.Parameter(p.getType().toString(), p.getId().getName()));
				}
			}

			if (n.getThrows() != null) {
				for (NameExpr ne : n.getThrows()) {
					theMethod.exceptions.add(new Exception(ne.toString()));
				}
			}
			current.methods.add(theMethod);

			return current;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Object visit(FieldDeclaration n, Object arg) {
			ClassInterface current = (ClassInterface) arg;

			for (VariableDeclarator vd : n.getVariables()) {
				Field f = new Field(n.getType().toString(), vd.getId().getName());
				f.isStatic = Modifier.isStatic(n.getModifiers());
				f.visibility = getModifiersAsString(n.getModifiers());
				current.fields.add(f);
			}
			super.visit(n, current);
			return current;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Object visit(ConstructorDeclaration n, Object arg) {
			ClassInterface current = (ClassInterface) arg;
			Constructor theConstructor = new Constructor(n.getName());

			super.visit(n, current);

			if (n.getParameters() != null) {
				for (Parameter p : n.getParameters()) {
					theConstructor.parameters.add(new de.uni.trier.infsec.tools.envgen.SystemInterface.Parameter(p.getType().toString(), p.getId().getName()));
				}
			}

			if (n.getThrows() != null) {
				for (NameExpr ne : n.getThrows()) {
					theConstructor.exceptions.add(new Exception(ne.toString()));
				}
			}
			current.constructors.add(theConstructor);

			return current;
		}

	}

	public static String getModifiersAsString(int modifier) {
		String out = "";
		if (Modifier.isPublic(modifier)) {
			out += "public";
		}
		if (Modifier.isAbstract(modifier)) {
			out += "abstract";
		}
		if (Modifier.isFinal(modifier)) {
			out += "final";
		}
		if (Modifier.isNative(modifier)) {
			out += "native";
		}
		if (Modifier.isPrivate(modifier)) {
			out += "private";
		}
		if (Modifier.isProtected(modifier)) {
			out += "protected";
		}
		if (Modifier.isStrict(modifier)) {
			out += "strict";
		}
		if (Modifier.isSynchronized(modifier)) {
			out += "synchronized";
		}
		if (Modifier.isTransient(modifier)) {
			out += "transient";
		}
		if (Modifier.isVolatile(modifier)) {
			out += "volatile";
		}
		return out;
	}
}
