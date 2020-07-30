/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ranger.authorization.presto.authorizer;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.SystemAccessControl;
import io.prestosql.spi.security.SystemSecurityContext;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;

import javax.inject.Inject;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static final String RANGER_PLUGIN_TYPE = "presto";
  private static final String RANGER_PRESTO_AUTHORIZER_IMPL_CLASSNAME = "org.apache.ranger.authorization.presto.authorizer.RangerSystemAccessControl";

  final private RangerPluginClassLoader rangerPluginClassLoader;
  final private SystemAccessControl systemAccessControlImpl;

  @Inject
  public RangerSystemAccessControl(RangerConfig config) {
    try {
      rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

      @SuppressWarnings("unchecked")
      Class<SystemAccessControl> cls = (Class<SystemAccessControl>) Class.forName(RANGER_PRESTO_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

      activatePluginClassLoader();

      Map<String, String> configMap = new HashMap<>();
      if (config.getKeytab() != null && config.getPrincipal() != null) {
        configMap.put("ranger.keytab", config.getKeytab());
        configMap.put("ranger.principal", config.getPrincipal());
      }
      systemAccessControlImpl = cls.getDeclaredConstructor(Map.class).newInstance(configMap);
    } catch (Exception e) {
      throw new RuntimeException(e);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetUser(principal, userName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetUser(principal, userName);
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSystemSessionProperty(context, propertyName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAccessCatalog(context, catalogName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
    return catalogs;
  }

  @Override
  public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateSchema(context, schema);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropSchema(context, schema);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameSchema(context, schema, newSchemaName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  @Override
  public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowSchemas(context, catalogName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowSchemas();
    }
  }

  @Override
  public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
    return schemaNames;
  }

  @Override
  public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameTable(context, table, newTable);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanShowTablesMetadata(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowTablesMetadata(context, schema);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
    }
  }

  @Override
  public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
    return tableNames;
  }

  @Override
  public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAddColumn(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropColumn(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameColumn(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSelectFromColumns(context, table, columns);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
    }
  }

  @Override
  public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanInsertIntoTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDeleteFromTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateView(context, view);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropView(context, view);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateViewWithSelectFromColumns(context, table, columns);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), context.getIdentity());
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetCatalogSessionProperty(context, catalogName, propertyName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

  private void activatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.activate();
    }
  }

  private void deactivatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.deactivate();
    }
  }
}
