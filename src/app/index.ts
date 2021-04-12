import registration from "./registration";
import authentication from "./authentication";
import metadataService from "./metadata-service";

export default async ({ expressApp }) => {
  await authentication({ app: expressApp });
  await registration({ app: expressApp });
  await metadataService({ app: expressApp });
};
