package de.uni.trier.infsec.tools.envgen.test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.tools.envgen.EnvGen;

public class TestGeneration extends TestCase {

	// @Test
	// public void testGeneration() throws Exception {
	// File fIn = new File(this.getClass().getResource("TestClassSystemGeneration.avaj").toURI());
	// File fDir = new File(System.getProperty("java.io.tmpdir") + "/evoting-system/");
	// if (!fDir.exists()) fDir.mkdirs();
	// EnvGen.main(new String[] {fIn.getAbsolutePath(), fDir.getAbsolutePath()});
	// }

	@Test
	public void testGeneration() throws Exception {
		String path = "YOUR PATH TO THE PACKAGE GOES HERE";
		
		try {
			new File(path);
		} catch (Exception e) {
			fail("Invalid Path!");
		}
		
		File fDir = new File(System.getProperty("java.io.tmpdir") + File.separator + "evoting-system");
		File faccept = new File(System.getProperty("java.io.tmpdir") + File.separator + "evoting-system" + File.separator + "accepted.lst");

		BufferedWriter bw = new BufferedWriter(new FileWriter(faccept));
		bw.write("Exception\n");
		bw.flush();
		bw.close();

		File fIn = new File(path);
		
		if (!fDir.exists()) fDir.mkdirs();
		
		EnvGen.main(new String[] { fIn.getAbsolutePath(), fDir.getAbsolutePath(), faccept.getAbsolutePath(), "de.uni.trier.infsec.environment" });
	}

}
