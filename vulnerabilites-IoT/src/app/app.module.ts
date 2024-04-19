import { NgModule } from '@angular/core';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { AppComponent } from './app.component';
import { HttpModule } from '@angular/http';
import { HttpClientModule } from '@angular/common/http';
import { VulnerabilityService } from './vulnerability.service';
import { CveTableComponent } from './cve-table/cve-table.component';
//import { HouseModule } from './Modules/house/house.module';

@NgModule({
  declarations:[CveTableComponent],
  imports: [
    MatIconModule,HttpClientModule
  ],
  providers: [
    MatIconRegistry, VulnerabilityService, HttpClientModule
  ],
  bootstrap: []
})
export class AppModule { }