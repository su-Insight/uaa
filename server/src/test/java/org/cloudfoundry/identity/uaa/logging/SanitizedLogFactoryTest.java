package org.cloudfoundry.identity.uaa.logging;

import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SanitizedLogFactoryTest {

    Logger mockLog;

    @Before
    public void setUp() {
        mockLog = mock(Logger.class);
    }

    @Test
    public void testSanitizeDebug() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isDebugEnabled();
        log.debug("one\ntwo\tthree\rfour");
        verify(mockLog).debug("one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeDebugCleanMessage() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isDebugEnabled();
        log.debug("one two three four");
        verify(mockLog).debug("one two three four");
    }

    @Test
    public void testSanitizeDebugCleanMessageException() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isDebugEnabled();
        Exception exception = new Exception("");
        log.debug("one two three four", exception);
        verify(mockLog).debug("one two three four", exception);
    }

    @Test
    public void testSanitizeInfo() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isInfoEnabled();
        log.info("one\ntwo\tthree\rfour");
        verify(mockLog).info("one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeInfoCleanMessage() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isInfoEnabled();
        log.info("one two three four");
        verify(mockLog).info("one two three four");
    }

    @Test
    public void testSanitizeWarn() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isWarnEnabled();
        log.warn("one\ntwo\tthree\rfour");
        verify(mockLog).warn("one|two|three|four[SANITIZED]");
    }

    @Test
    public void testSanitizeWarnCleanMessage() {
        SanitizedLogFactory.SanitizedLog log = new SanitizedLogFactory.SanitizedLog(mockLog);
        doReturn(true).when(mockLog).isWarnEnabled();
        log.warn("one two three four");
        verify(mockLog).warn("one two three four");
    }

}