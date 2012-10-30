package de.uni.trier.infsec.tools.envgen.test;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.tools.envgen.Main;


public class TestGeneration extends TestCase {

	
	
	@Test
	public void testGeneration() throws Exception {
		File fIn = new File(this.getClass().getResource("TestClassSystemGeneration.avaj").toURI());
		File fDir = new File(System.getProperty("java.io.tmpdir") + "evoting-system/");
		if (!fDir.exists()) fDir.mkdirs();
		Main.main(new String[] {fIn.getAbsolutePath(), fDir.getAbsolutePath()});
	}
	
}
