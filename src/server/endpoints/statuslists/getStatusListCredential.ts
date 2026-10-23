import { Request, Response } from 'express';
import { Issuer } from '#root/issuer/Issuer';
import { StatusListOptions } from '#root/types/internal/statuslists';
import { StatusListType } from '#root/statusLists/StatusListType';

export function getStatusListCredential(issuer:Issuer, statusListOptions:StatusListOptions, path:string) {
    issuer.router!.get(
        path + "/:index",
        async (request: Request, response: Response<string>) => {
            try {
                const statusList = new StatusListType(statusListOptions, issuer);
                response.setHeader('Content-type', statusList.getSpecType() == 'ietf' ? 'application/statuslist+jwt' : 'application/vc+jwt');
                response.send(await statusList.getListCredential(parseInt(request.params.index as string), issuer));
            } catch {
                response.status(404).end('List not found');
            }
        });
}