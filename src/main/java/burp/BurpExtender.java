/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package burp;

import swurg.ui.Tab;
import java.io.PrintWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BurpExtender implements IBurpExtender {

  public static String COPYRIGHT = "Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved";
  public static String EXTENSION = "OpenAPI Parser";
  private static IBurpExtenderCallbacks callbacks;
  private static BurpExtender instance;
  private IExtensionHelpers helpers;

  
  public static BurpExtender getInstance() {
    if(instance==null)
       instance = new BurpExtender();
    return instance;
  }

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    this.helpers = callbacks.getHelpers();
    Tab tab = new Tab(callbacks);
    ContextMenuFactory contextMenuFactory = new ContextMenuFactory(callbacks, tab);

    callbacks.setExtensionName(EXTENSION);
    callbacks.addSuiteTab(tab);
    callbacks.customizeUiComponent(tab.getUiComponent());
    callbacks.printOutput(String.format("%s tab initialised", EXTENSION));
    callbacks.registerContextMenuFactory(contextMenuFactory);
    callbacks.printOutput(String.format("'Send to %s' option added to the context menu", EXTENSION));

    instance = this;

    PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
    PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  public IBurpExtenderCallbacks getCallbacks() {
    return callbacks;
  }

  public IExtensionHelpers getHelpers() {
    return helpers;
  }

}
